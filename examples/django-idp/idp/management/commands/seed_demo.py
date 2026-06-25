"""Create a demo admin and a set of demo users (idempotent). DEMO ONLY."""
import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

# Demo users with Swedish surnames; all share one demo password and live on the
# @gamlastan.sverige domain. Usernames are the lowercased first name.
EMAIL_DOMAIN = "gamlastan.sverige"
DEMO_USERS = [
    ("Angela", "Andersson"),
    ("Pamela", "Pettersson"),
    ("Sandra", "Svensson"),
    ("Monica", "Magnusson"),
    ("Erica", "Eriksson"),
    ("Rita", "Rosén"),
    ("Tina", "Törnqvist"),
    ("Jessica", "Johansson"),
]


class Command(BaseCommand):
    help = "Create a demo superuser and a set of demo end users if they do not exist."

    def handle(self, *args, **options):
        User = get_user_model()

        admin_username = os.environ.get("DJANGO_ADMIN_USERNAME", "admin")
        admin_password = os.environ.get("DJANGO_ADMIN_PASSWORD", "admin")
        if not User.objects.filter(username=admin_username).exists():
            User.objects.create_superuser(
                admin_username, f"{admin_username}@{EMAIL_DOMAIN}", admin_password
            )
            self.stdout.write(self.style.SUCCESS(f"Created superuser {admin_username!r}"))

        password = os.environ.get("DEMO_PASSWORD", "gamlastan")
        for first, last in DEMO_USERS:
            username = first.lower()
            if User.objects.filter(username=username).exists():
                continue
            user = User.objects.create_user(
                username, f"{username}@{EMAIL_DOMAIN}", password
            )
            user.first_name, user.last_name = first, last
            user.save()
            self.stdout.write(self.style.SUCCESS(f"Created demo user {username!r}"))
