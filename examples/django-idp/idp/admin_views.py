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

from .accounts import prepare_user, replace_password
from .admin_forms import AccountForm, BlockedRecoveryEmailsForm
from .models import BlockedRecoveryEmail, User


def administrator_required(view):
    @wraps(view)
    @never_cache
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path())
        if not request.user.is_active or not request.user.is_staff:
            raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapped


def check_administrator(request):
    # Recheck privileges inside the write transaction, including on SQLite.
    if not User.objects.filter(pk=request.user.pk, is_active=True, is_staff=True).exists():
        raise PermissionDenied


def validation_message(exc):
    return " ".join(exc.messages) if isinstance(exc, ValidationError) else "Account conflicts with an existing account."


@administrator_required
@require_http_methods(["GET"])
def user_list(request):
    query = request.GET.get("q", "").strip()
    users = User.objects.order_by("username")
    if query:
        users = users.filter(Q(username__icontains=query) | Q(email__icontains=query)
                             | Q(display_name__icontains=query))
    page = Paginator(users, 50).get_page(request.GET.get("page"))
    return render(request, "idp/admin_users.html", {"page": page, "query": query})


@administrator_required
@require_http_methods(["GET", "POST"])
def blocked_emails(request):
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
    with transaction.atomic():
        check_administrator(request)
        get_object_or_404(BlockedRecoveryEmail, pk=pk).delete()
    messages.success(request, "Email address removed from the blocked list.")
    return redirect("idp_admin:blocked_emails")


@administrator_required
@sensitive_post_parameters()
@require_http_methods(["GET", "POST"])
def user_edit(request, pk=None):
    account = get_object_or_404(User, pk=pk) if pk is not None else None
    if request.method == "POST":
        try:
            with transaction.atomic():
                check_administrator(request)
                # Reload rather than overwrite account changes from a stale read.
                account = get_object_or_404(User, pk=pk) if pk is not None else None
                form = AccountForm(request.POST, instance=account)
                if form.is_valid():
                    if account is None:
                        data = form.cleaned_data
                        user, password, _ = prepare_user(
                            username=data["username"], email=data["email"], admin=data["is_staff"],
                            **{key: data[key] for key in ("first_name", "last_name", "display_name",
                                                        "scoped_affiliation", "is_active")})
                        user.save()
                    else:
                        user = form.save()
                        password = None
                    form.save_groups(user)
                else:
                    user = None
            if user is not None:
                if password is not None:
                    return render(request, "idp/admin_password.html", {"account": user, "password": password})
                messages.success(request, "Account updated.")
                return redirect("idp_admin:users")
        except (ValidationError, IntegrityError) as exc:
            form.add_error(None, validation_message(exc))
    else:
        form = AccountForm(instance=account)
    return render(request, "idp/admin_user_form.html", {"form": form, "account": account})


@administrator_required
@sensitive_post_parameters()
@require_http_methods(["GET", "POST"])
def user_action(request, pk, action):
    account = get_object_or_404(User, pk=pk)
    error = None
    if request.method == "POST":
        try:
            with transaction.atomic():
                check_administrator(request)
                account = get_object_or_404(User, pk=pk)
                if action == "delete":
                    account.delete()
                else:
                    account, password = replace_password(account.username)
            if action == "reset":
                return render(request, "idp/admin_password.html", {"account": account, "password": password})
            messages.success(request, "Account deleted.")
            return redirect("idp_admin:users")
        except (ValidationError, IntegrityError) as exc:
            error = validation_message(exc)
    return render(request, "idp/admin_confirm.html", {"account": account, "action": action, "error": error})
