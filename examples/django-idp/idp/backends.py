from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q

from .models import normalize_identifier


class IdentifierBackend(ModelBackend):
    """Authenticate a normalized username or email without ambiguous matches."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return None
        User = get_user_model()
        identifier = normalize_identifier(username)
        try:
            user = User.objects.get(Q(username=identifier) | Q(email=identifier))
        except (User.DoesNotExist, User.MultipleObjectsReturned):
            User().set_password(password)  # Equalize the expensive hash operation.
            return None
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
