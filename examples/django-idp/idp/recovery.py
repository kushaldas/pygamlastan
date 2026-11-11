"""Password recovery using Django tokens, mailers, and shared SQLite quotas."""
import math
from datetime import timedelta
from ipaddress import ip_address, ip_network

from django.conf import settings
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.views import (
    INTERNAL_RESET_SESSION_TOKEN, PasswordResetConfirmView, PasswordResetView,
)
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.crypto import salted_hmac
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from .models import BlockedRecoveryEmail, RecoveryRateLimit, RecoveryRequest, User, normalize_identifier


def recovery_blocked(email):
    """Check the blocklist using the same normalization as account email."""
    return BlockedRecoveryEmail.objects.filter(email=normalize_identifier(email)).exists()


def client_ip(request):
    """Walk forwarding hops right-to-left, stopping at the first untrusted peer."""
    networks = [ip_network(value) for value in settings.SAML_IDP_TRUSTED_PROXIES]
    try:
        peer = ip_address(request.META.get("REMOTE_ADDR", ""))
    except ValueError:
        return "unknown"
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")
    for value in reversed(forwarded):
        if not any(peer in network for network in networks):
            break
        try:
            peer = ip_address(value.strip())
        except ValueError:
            break
    return str(peer)


def consume_limits(quotas):
    """Consume ordered quotas atomically, stopping at the first exhausted quota."""
    now = timezone.now()
    blocked = {}
    with transaction.atomic():
        RecoveryRateLimit.objects.filter(expires_at__lte=now).delete()
        for kind, identifier, limit, seconds in quotas:
            key = salted_hmac("idp.recovery." + kind, identifier, algorithm="sha256").hexdigest()
            bucket, _ = RecoveryRateLimit.objects.select_for_update().get_or_create(
                key=key, defaults={"expires_at": now + timedelta(seconds=seconds)})
            if bucket.count >= limit:
                blocked[kind] = max(1, math.ceil((bucket.expires_at - now).total_seconds()))
                # An exhausted IP must not create unlimited email buckets.
                break
            else:
                bucket.count += 1
                bucket.save(update_fields=["count"])
    return blocked


def too_many_requests(seconds):
    """Return a throttled response with the remaining quota-window delay."""
    response = HttpResponse("Too many password reset attempts. Please try again later.", status=429)
    response["Retry-After"] = str(seconds)
    return response


class RecoveryForm(PasswordResetForm):
    """Reuse Django reset tokens with current eligibility and delivery-time blocking."""
    requested_at = None

    def clean_email(self):
        """Normalize an already validated email address for quotas and lookup."""
        return normalize_identifier(self.cleaned_data["email"])

    def get_users(self, email):
        """Select currently eligible accounts that existed when the request was queued."""
        if recovery_blocked(email):
            return ()
        return (user for user in super().get_users(email)
                if self.requested_at is None or user.date_joined <= self.requested_at)

    def send_mail(self, subject_template_name, email_template_name, context, from_email,
                  to_email, html_email_template_name=None):
        """Recheck recipient blocking immediately before SMTP or console delivery."""
        # Recheck at delivery time, including when using the console mailer.
        if recovery_blocked(to_email):
            return
        return super().send_mail(subject_template_name, email_template_name, context,
                                 from_email, to_email, html_email_template_name)


def process_recovery_request():
    """Claim one queued request, send outside the write lock, and remove its address."""
    now = timezone.now()
    with transaction.atomic():
        # Discard requests older than a reset link's lifetime, including crashed claims.
        RecoveryRequest.objects.filter(created_at__lt=now - timedelta(hours=1)).delete()
        job = (RecoveryRequest.objects.select_for_update()
               .filter(available_at__lte=now).order_by("pk").first())
        if job is None:
            return False
        # A worker crash leaves a bounded lease; another worker can reclaim it.
        timeout = settings.MAILERS["default"].get("OPTIONS", {}).get("timeout") or 15
        job.available_at = now + timedelta(seconds=max(300, timeout + 60))
        job.save(update_fields=["available_at"])

    try:
        form = RecoveryForm({"email": job.email})
        form.requested_at = job.created_at
        if form.is_valid():
            form.save(
                domain_override="IdP", from_email=settings.DEFAULT_FROM_EMAIL,
                email_template_name="idp/password_reset_email.txt",
                subject_template_name="idp/password_reset_subject.txt",
                extra_email_context={"reset_base_url": settings.SAML_IDP_BASE_URL},
            )
    finally:
        # Django logs SMTP failures without raising. Do not retry them or fall back
        # to console delivery; the owner can request another link under the quotas.
        RecoveryRequest.objects.filter(pk=job.pk).delete()
    return True


@method_decorator(never_cache, name="dispatch")
@method_decorator(require_http_methods(["GET", "POST"]), name="dispatch")
class RecoveryView(PasswordResetView):
    """Apply quotas and queue addresses without disclosing account eligibility."""
    form_class = RecoveryForm
    template_name = "idp/password_reset_form.html"
    success_url = reverse_lazy("idp:password_reset_done")

    def post(self, request, *args, **kwargs):
        """Charge shared request quotas before validating or queueing the supplied address."""
        # Charge even unknown addresses and malformed submissions identically.
        self.blocked = consume_limits([
            ("request-ip", client_ip(request), settings.SAML_IDP_RESET_IP_LIMIT, 900),
            ("request-email", normalize_identifier(request.POST.get("email", "")),
             settings.SAML_IDP_RESET_EMAIL_LIMIT, 3600),
        ])
        if "request-ip" in self.blocked:
            return too_many_requests(self.blocked["request-ip"])
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        """Queue permitted addresses without checking eligibility or sending mail."""
        if "request-email" not in self.blocked:
            # No user/blocklist lookup or mail delivery may occur on this path:
            # every permitted address receives exactly the same queue operation.
            RecoveryRequest.objects.create(email=form.cleaned_data["email"])
        return redirect(self.success_url)


@method_decorator(never_cache, name="dispatch")
@method_decorator(require_http_methods(["GET", "POST"]), name="dispatch")
class RecoveryConfirmView(PasswordResetConfirmView):
    """Accept a valid reset token once, with transactional policy revalidation."""
    template_name = "idp/password_reset_confirm.html"
    success_url = reverse_lazy("idp:password_reset_complete")

    def dispatch(self, request, *args, **kwargs):
        """Throttle completion attempts before token and password processing."""
        if request.method == "POST":
            blocked = consume_limits([
                ("confirm-ip", client_ip(request), settings.SAML_IDP_RESET_CONFIRM_LIMIT, 900),
            ])
            if "confirm-ip" in blocked:
                return too_many_requests(blocked["confirm-ip"])
        return super().dispatch(request, *args, **kwargs)

    def get_user(self, uidb64):
        """Reject disabled, unusable-password, or blocked accounts before displaying a reset form."""
        user = super().get_user(uidb64)
        return user if (user and user.is_active and user.has_usable_password()
                        and not recovery_blocked(user.email)) else None

    def form_valid(self, form):
        """Revalidate the token under the write lock before committing the password."""
        # Hash outside the write lock. Recheck the token and active status while
        # holding it so concurrent resets/replacements cannot reuse a token.
        prepared = form.save(commit=False)
        token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
        with transaction.atomic():
            user = User.objects.select_for_update().filter(pk=prepared.pk, is_active=True).first()
            if (user is None or recovery_blocked(user.email)
                    or not self.token_generator.check_token(user, token)):
                self.validlink = False
                return self.render_to_response(self.get_context_data())
            user.password = prepared.password
            user.save(update_fields=["password"])
        self.request.session.pop(INTERNAL_RESET_SESSION_TOKEN, None)
        return redirect(self.success_url)
