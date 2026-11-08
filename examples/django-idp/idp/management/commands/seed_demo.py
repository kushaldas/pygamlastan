"""Opt-in lesson accounts; never called at HTTP startup."""
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError

from idp.accounts import commit_users, prepare_user
from idp.models import User

DEMO_USERS = [
    ("Angela", "Andersson"), ("Pamela", "Pettersson"), ("Sandra", "Svensson"),
    ("Monica", "Magnusson"), ("Erica", "Eriksson"), ("Rita", "Rosén"),
    ("Tina", "Törnqvist"), ("Jessica", "Johansson"),
]


class Command(BaseCommand):
    help = "Explicitly seed lesson users with individual random passwords (no administrator)."

    def add_arguments(self, parser):
        parser.add_argument("--password-stdin", action="store_true")
        parser.add_argument("--allow-weak-password", action="store_true")

    def handle(self, *args, **options):
        from .idp_user import password_options

        kwargs = password_options(options)
        try:
            prepared = [
                prepare_user(username=first.lower(), email=f"{first.lower()}@gamlastan.sverige",
                             first_name=first, last_name=last, **kwargs)
                for first, last in DEMO_USERS
                if not User.objects.filter(username=first.lower()).exists()
            ]
            commit_users(prepared)
        except (ValidationError, IntegrityError) as exc:
            message = "; ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc)
            raise CommandError(message) from exc
        for user, password, _ in prepared:
            self.stdout.write(f"{user.username}: generated password (shown once): {password}"
                              if password is not None else f"{user.username}: password set from stdin.")
        self.stdout.write(f"Created {len(prepared)} lesson account(s).")
