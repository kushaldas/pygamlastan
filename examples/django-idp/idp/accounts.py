"""Validated account mutations. Never return credentials before commit."""
from django.contrib.auth.models import Group
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import transaction

from .models import User, normalize_identifier
from .passwords import generate_password


def prepare_user(*, username, email, password=None, allow_weak_password=False,
                 admin=False, groups=(), **profile):
    allowed = {"first_name", "last_name", "display_name", "scoped_affiliation", "is_active"}
    if set(profile) - allowed:
        raise ValidationError("Unsupported account profile fields.")
    if not isinstance(groups, (list, tuple)) or any(
        not isinstance(name, str) or not name.strip() or len(name) > 150 for name in groups
    ):
        raise ValidationError("Groups must be a list of nonempty names up to 150 characters.")
    user = User(username=normalize_identifier(username), email=normalize_identifier(email),
                is_staff=admin, **profile)
    user.full_clean(exclude=["password"])
    generated = password is None
    password = generate_password() if generated else password
    if not password or len(password) > 128:
        raise ValidationError("Password must contain between 1 and 128 characters.")
    if not allow_weak_password:
        validate_password(password, user)
    user.set_password(password)
    return user, (password if generated else None), tuple(dict.fromkeys(groups))


def commit_users(prepared):
    """Commit an entire prevalidated batch, rolling back on any conflict."""
    with transaction.atomic():
        for user, _, groups in prepared:
            user.save()
            user.groups.set([Group.objects.get_or_create(name=name)[0] for name in groups])


def create_user(**kwargs):
    prepared = prepare_user(**kwargs)
    commit_users([prepared])
    return prepared[0], prepared[1]


def replace_password(username, *, password=None, allow_weak_password=False):
    # Hashing is deliberately outside the SQLite write transaction.
    user = User.objects.get(username=normalize_identifier(username))
    generated = password is None
    password = generate_password() if generated else password
    if not password or len(password) > 128:
        raise ValidationError("Password must contain between 1 and 128 characters.")
    if not allow_weak_password:
        validate_password(password, user)
    user.set_password(password)
    user.save(update_fields=["password"])
    return user, (password if generated else None)


def set_admin(username, enabled):
    with transaction.atomic():
        user = User.objects.get(username=normalize_identifier(username))
        user.is_staff = enabled
        user.save(update_fields=["is_staff"])
    return user
