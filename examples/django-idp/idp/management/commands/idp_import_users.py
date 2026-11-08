from pathlib import Path

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError

from idp.accounts import commit_users
from idp.legacy_users import prepare_import


class Command(BaseCommand):
    help = "Atomically import legacy JSON profiles with fresh random passwords and no admin grants."

    def add_arguments(self, parser):
        parser.add_argument("file")

    def handle(self, *args, **options):
        try:
            prepared = prepare_import(Path(options["file"]).read_text(encoding="utf-8"))
            commit_users(prepared)
        except (OSError, ValueError, ValidationError, IntegrityError) as exc:
            message = "; ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc)
            raise CommandError(message) from exc
        for user, password, _ in prepared:
            self.stdout.write(f"{user.username}: generated password (shown once): {password}")
        self.stdout.write(f"Imported {len(prepared)} account(s).")
