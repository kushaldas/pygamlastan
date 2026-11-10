"""Staff-only account administration, separate from Django's built-in admin."""
from functools import wraps

from django.contrib import messages
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods

from .accounts import prepare_password, prepare_user
from .admin_forms import AccountForm, BlockedRecoveryEmailsForm
from .models import BlockedRecoveryEmail, User, normalize_identifier


def administrator_required(view):
    """Require an active administrator and prevent caching of administrative responses."""
    @wraps(view)
    @never_cache
    def wrapped(request, *args, **kwargs):
        """Redirect anonymous users and reject authenticated non-administrators."""
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path())
        if not request.user.is_active or not request.user.is_staff:
            raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapped


def check_administrator(request):
    """Recheck current privileges inside the transaction that changes account data."""
    # Recheck privileges inside the write transaction, including on SQLite.
    if not User.objects.filter(pk=request.user.pk, is_active=True, is_staff=True).exists():
        raise PermissionDenied


def validation_message(exc):
    """Expose validation errors while keeping database conflict details private."""
    return " ".join(exc.messages) if isinstance(exc, ValidationError) else "Account conflicts with an existing account."


@administrator_required
@require_http_methods(["GET"])
def user_list(request):
    """Search normalized identifiers and original display names, then paginate accounts."""
    query = request.GET.get("q", "").strip()
    users = User.objects.order_by("username")
    if query:
        identifier = normalize_identifier(query)
        users = users.filter(Q(username__icontains=identifier) | Q(email__icontains=identifier)
                             | Q(display_name__icontains=query))
    page = Paginator(users, 50).get_page(request.GET.get("page"))
    return render(request, "idp/admin_users.html", {"page": page, "query": query})


@administrator_required
@require_http_methods(["GET", "POST"])
def blocked_emails(request):
    """List blocked addresses and atomically add a fully validated address batch."""
    form = BlockedRecoveryEmailsForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            check_administrator(request)
            added = sum(
                BlockedRecoveryEmail.objects.get_or_create(email=email)[1]
                for email in form.cleaned_data["emails"]
            )
        messages.success(request, f"Added {added} blocked email address(es).")
        return redirect("idp_admin:blocked_emails")
    page = Paginator(BlockedRecoveryEmail.objects.all(), 50).get_page(request.GET.get("page"))
    return render(request, "idp/admin_blocked_emails.html", {"form": form, "page": page})


@administrator_required
@require_http_methods(["POST"])
def blocked_email_remove(request, pk):
    """Remove one blocked address through an administrator-authorized POST."""
    with transaction.atomic():
        check_administrator(request)
        get_object_or_404(BlockedRecoveryEmail, pk=pk).delete()
    messages.success(request, "Email address removed from the blocked list.")
    return redirect("idp_admin:blocked_emails")


@administrator_required
@sensitive_post_parameters()
@require_http_methods(["GET", "POST"])
def user_edit(request, pk=None):
    """Create or update an account and show generated credentials only after commit."""
    account = get_object_or_404(User, pk=pk) if pk is not None else None
    form = AccountForm(request.POST if request.method == "POST" else None, instance=account)
    if request.method == "POST":
        try:
            user, password = None, None
            if form.is_valid():
                if pk is None:
                    data = form.cleaned_data
                    # Password hashing must finish before SQLite takes its
                    # IMMEDIATE write lock for authorization and persistence.
                    user, password, _ = prepare_user(
                        username=data["username"], email=data["email"], admin=data["is_staff"],
                        **{key: data[key] for key in ("first_name", "last_name", "display_name",
                                                    "scoped_affiliation", "is_active")})
                with transaction.atomic():
                    check_administrator(request)
                    if pk is None:
                        # User.save revalidates uniqueness and model invariants.
                        user.save()
                    else:
                        account = get_object_or_404(User, pk=pk)
                        form = AccountForm(request.POST, instance=account)
                        user = form.save() if form.is_valid() else None
                    if user is not None:
                        form.save_groups(user)
            if user is not None:
                if password is not None:
                    return render(request, "idp/admin_password.html", {"account": user, "password": password})
                messages.success(request, "Account updated.")
                return redirect("idp_admin:users")
        except (ValidationError, IntegrityError) as exc:
            form.add_error(None, validation_message(exc))
    return render(request, "idp/admin_user_form.html", {"form": form, "account": account})


@administrator_required
@sensitive_post_parameters()
@require_http_methods(["GET", "POST"])
def user_action(request, pk, action):
    """Confirm deletion or password replacement while retaining model safeguards."""
    account = get_object_or_404(User, pk=pk)
    error = None
    if request.method == "POST":
        try:
            prepared = account
            if action == "reset":
                password = prepare_password(prepared)
            with transaction.atomic():
                check_administrator(request)
                account = get_object_or_404(User, pk=pk)
                if action == "delete":
                    account.delete()
                else:
                    account.password = prepared.password
                    # Preserve Django's password_changed callbacks without hashing
                    # again or overwriting profile changes made during hashing.
                    account._password = prepared._password
                    account.save(update_fields=["password"])
            if action == "reset":
                return render(request, "idp/admin_password.html", {"account": account, "password": password})
            messages.success(request, "Account deleted.")
            return redirect("idp_admin:users")
        except (ValidationError, IntegrityError) as exc:
            error = validation_message(exc)
    return render(request, "idp/admin_confirm.html", {"account": account, "action": action, "error": error})
