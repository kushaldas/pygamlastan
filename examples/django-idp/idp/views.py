"""IdP HTTP endpoints: home, metadata, SSO (Redirect + POST), login, logout, error."""
from django.contrib.auth import authenticate, login, update_session_auth_hash
from django.contrib.auth.views import PasswordChangeView
from django.contrib import messages
from django.contrib.sessions.models import Session
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect, render
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from django.conf import settings

from . import saml_logic as sl
from . import sp_resolver
from . import slo
from .idp_config import get_idp_config
from .models import SamlParticipant, User

# Session key holding the in-flight AuthnRequest while the user logs in.
PENDING = "saml_pending"


def _error(request, message, status=400):
    """Render the error page (the metadata errorURL target) with a message."""
    return render(
        request,
        "idp/error.html",
        {"message": message, "cfg": get_idp_config()},
        status=status,
    )


def index(request):
    cfg = get_idp_config()
    return render(
        request,
        "idp/index.html",
        {
            "cfg": cfg,
            "mdq_url": settings.SAML_IDP_MDQ_URL,
            "metadata_cert": settings.SAML_IDP_METADATA_CERT,
            "file_sp_count": sp_resolver.file_sp_count(),
        },
    )


def metadata(request):
    cfg = get_idp_config()
    return HttpResponse(
        sl.idp_metadata_xml(cfg), content_type="application/samlmetadata+xml"
    )


@require_http_methods(["GET"])
def error(request):
    """The errorURL target (SWAMID Tech 5.1.13). SPs may send a user here when
    SSO fails; the SAML errorURL context params are surfaced if present."""
    context = {
        k: request.GET[k]
        for k in (
            "errorURL_code", "errorURL_ts", "errorURL_rp", "errorURL_tid",
            "errorURL_ctx",
        )
        if k in request.GET
    }
    return render(
        request,
        "idp/error.html",
        {"message": None, "context": context, "cfg": get_idp_config()},
    )


@csrf_exempt  # the SAML POST binding is a cross-origin form post from the SP
@require_http_methods(["GET", "POST"])
def sso(request):
    try:
        decoded = sl.decode_authn_request(
            request.method, request.META.get("QUERY_STRING", ""), request.POST
        )
        # Strict UTF-8, never decoded.saml_text: that projection is lossy
        # (invalid bytes become U+FFFD, display/logging only), so the bytes the
        # binding authenticated could differ from the XML parsed and verified
        # below. Malformed input must be rejected, not transformed.
        saml_text = decoded.saml_xml.decode("utf-8")
        relay_state = decoded.relay_state
        authn = sl.parse_authn(saml_text)
    except Exception as exc:  # noqa: BLE001
        return _error(request, f"Could not decode the AuthnRequest: {exc}")

    issuer = authn.issuer.value if authn.issuer else None
    # Resolve the SP from a local file or MDQ; remote metadata must verify.
    sp_metadata_xml = sp_resolver.resolve(issuer)
    if sp_metadata_xml is None:
        return _error(
            request,
            f"The Service Provider {issuer!r} could not be resolved "
            "(not found, or its metadata signature did not verify).",
        )

    try:
        # Verifies the request signature against the SP metadata and enforces the
        # SP's AuthnRequestsSigned policy before the request is acted on.
        processed = sl.process_authn(authn, saml_text, decoded, sp_metadata_xml)
    except Exception as exc:  # noqa: BLE001
        return _error(request, f"The AuthnRequest was rejected: {exc}")

    request.session[PENDING] = {
        "request_id": processed.request_id,
        "sp_entity_id": processed.sp_entity_id,
        "acs_url": processed.acs_url,
        "name_id_format": processed.requested_name_id_format,
        "relay_state": relay_state,
    }
    if not request.user.is_authenticated:
        return redirect(reverse("idp:login"))
    return _issue(request)


def _issue(request):
    """Build, sign and POST the response for the pending request. Caller ensures
    the user is authenticated."""
    pending = request.session.pop(PENDING, None)
    if not pending:
        return redirect("idp:index")
    cfg = get_idp_config()
    signed = sl.build_signed_response(
        sp_entity_id=pending["sp_entity_id"],
        acs_url=pending["acs_url"],
        request_id=pending["request_id"],
        name_id_format=pending["name_id_format"],
        user=request.user,
        cfg=cfg,
        # Real authentication time. When this AuthnRequest reused an existing
        # browser session the user authenticated earlier than now, so report
        # `last_login` rather than over-stating freshness to the SP.
        authn_instant=request.user.last_login,
    )
    html = sl.encode_post_response(signed, pending["acs_url"], pending["relay_state"])
    slo.record_issued(request, signed, pending["sp_entity_id"])
    return HttpResponse(html)


@require_http_methods(["GET", "POST"])
def login_view(request):
    pending = PENDING in request.session
    if request.method == "POST":
        user = authenticate(
            request,
            username=request.POST.get("username"),
            password=request.POST.get("password"),
        )
        if user is not None:
            login(request, user)
            if PENDING in request.session:
                return _issue(request)
            next_url = request.GET.get("next", "")
            if next_url and url_has_allowed_host_and_scheme(
                next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
            ):
                return HttpResponseRedirect(next_url)
            return redirect("idp:profile")
        return render(
            request,
            "idp/login.html",
            {"error": "Invalid username or password.", "pending": pending},
            status=401,
        )
    return render(request, "idp/login.html", {"pending": pending})


@method_decorator(never_cache, name="dispatch")
class ProfileView(PasswordChangeView):
    """Read-only account details and Django's current-password-verified change form."""
    template_name = "idp/profile.html"
    success_url = reverse_lazy("idp:profile")

    def form_valid(self, form):
        old_key = self.request.session.session_key
        old_hash = form.user.password
        # Hash outside the write transaction, then rotate the session and move
        # its SAML associations atomically so concurrent cleanup cannot lose them.
        user = form.save(commit=False)
        with transaction.atomic():
            if not Session.objects.filter(pk=old_key, expire_date__gt=timezone.now()).exists():
                # logout may have invalidated the cached session while hashing.
                # cycle_key() would otherwise create a fresh authenticated one.
                user.password = old_hash
                return HttpResponse("Your session has ended. Sign in again before changing your password.", status=409)
            if not User.objects.filter(pk=user.pk, password=old_hash, is_active=True).exists():
                user.password = old_hash
                form.add_error("old_password", "Your account changed. Please try again.")
                return self.form_invalid(form)
            user.save(update_fields=["password"])
            update_session_auth_hash(self.request, user)
            self.request.session.save()
            key = self.request.session.session_key
            expiry = Session.objects.values_list("expire_date", flat=True).get(pk=key)
            SamlParticipant.objects.filter(session_key=old_key).update(session_key=key, expires_at=expiry)
        messages.success(self.request, "Your password has been changed.")
        return redirect(self.get_success_url())
