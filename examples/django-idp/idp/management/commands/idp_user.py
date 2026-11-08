import sys

from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError

from idp import accounts
from idp.models import User


def add_password_options(parser):
    parser.add_argument("--password-stdin", action="store_true",
                        help="Read one password line from stdin; never pass passwords in argv.")
    parser.add_argument("--allow-weak-password", action="store_true",
                        help="Permit a short teaching password supplied via stdin.")


def password_options(options):
    if options["allow_weak_password"] and not options["password_stdin"]:
        raise CommandError("--allow-weak-password requires --password-stdin.")
    password = None
    if options["password_stdin"]:
        # Remove the line terminator only: intentional spaces are part of the password.
        password = sys.stdin.readline().removesuffix("\n").removesuffix("\r")
        if not password:
            raise CommandError("A nonempty password line is required on stdin.")
    return {"password": password, "allow_weak_password": options["allow_weak_password"]}


class Command(BaseCommand):
    help = "Create accounts, replace passwords, or grant/revoke IdP administration."

    def add_arguments(self, parser):
        commands = parser.add_subparsers(dest="operation", required=True)
        create = commands.add_parser("create")
        create.add_argument("username")
        create.add_argument("--email", required=True)
        create.add_argument("--admin", action="store_true")
        add_password_options(create)
        password = commands.add_parser("set-password")
        password.add_argument("username")
        add_password_options(password)
        admin = commands.add_parser("set-admin")
        admin.add_argument("username")
        toggle = admin.add_mutually_exclusive_group(required=True)
        toggle.add_argument("--enable", action="store_true")
        toggle.add_argument("--disable", action="store_true")

    def handle(self, *args, **options):
        try:
            if options["operation"] == "set-admin":
                user = accounts.set_admin(options["username"], options["enable"])
                self.stdout.write(f"{user.username}: administrator={user.is_staff}")
                return
            kwargs = password_options(options)
            if options["operation"] == "create":
                user, password = accounts.create_user(
                    username=options["username"], email=options["email"],
                    admin=options["admin"], **kwargs,
                )
            else:
                user, password = accounts.replace_password(options["username"], **kwargs)
        except (ValidationError, IntegrityError, User.DoesNotExist) as exc:
            message = "; ".join(exc.messages) if isinstance(exc, ValidationError) else str(exc)
            raise CommandError(message or "Account not found.") from exc
        self.stdout.write(f"Account: {user.username}")
        if password is not None:
            self.stdout.write(f"Generated password (shown once): {password}")
        else:
            self.stdout.write("Password set from stdin.")
