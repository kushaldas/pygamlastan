import secrets
import string

from django.core.exceptions import ValidationError


def generate_password():
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))


class PasswordLengthValidator:
    def validate(self, password, user=None):
        if not 15 <= len(password) <= 128:
            raise ValidationError("Use between 15 and 128 characters.", code="password_length")

    def get_help_text(self):
        return "Use 15–128 characters. Spaces are allowed."
