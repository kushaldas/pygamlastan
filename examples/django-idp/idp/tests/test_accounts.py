import io
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

from django.contrib.auth import authenticate
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import close_old_connections, connections
from django.test import Client, TestCase, TransactionTestCase

from idp import accounts
from idp.legacy_users import prepare_import
from idp.models import User


class AccountTests(TestCase):
    def create(self, username="alice", email="alice@example.org", **kwargs):
        return accounts.create_user(username=username, email=email, **kwargs)

    def test_normalized_login_by_either_identifier(self):
        user, password = self.create(username="Alice", email="ALICE@Example.org")
        self.assertEqual(user.username, "alice")
        self.assertEqual(user.email, "alice@example.org")
        for identifier in ["ALICE", "Alice@EXAMPLE.ORG", " alice "]:
            self.assertEqual(authenticate(username=identifier, password=password), user)
        self.assertIsNone(authenticate(username="alice", password="wrong"))
        self.assertIsNone(authenticate(username="unknown", password=password))
        user.is_active = False
        user.save()
        self.assertIsNone(authenticate(username="alice", password=password))

    def test_duplicate_and_cross_field_collisions(self):
        self.create()
        for username, email in [("ALICE", "other@example.org"),
                                ("other", "ALICE@EXAMPLE.ORG"),
                                ("alice@example.org", "other@example.org"),
                                ("other", "ALICE")]:
            with self.subTest(username=username, email=email), self.assertRaises(ValidationError):
                self.create(username=username, email=email)
        self.assertEqual(User.objects.count(), 1)

    def test_unicode_identifiers_normalize_before_validation(self):
        user, password = self.create(username="Ａlice")
        self.assertEqual(user.username, "alice")
        self.assertEqual(authenticate(username="ＡLICE", password=password), user)
        with self.assertRaises(ValidationError):
            self.create(username="alice", email="other@example.org")

    def test_required_valid_email(self):
        for email in ["", "invalid"]:
            with self.subTest(email=email), self.assertRaises(ValidationError):
                self.create(email=email)

    def test_password_generation_and_hash_storage(self):
        user, password = self.create()
        self.assertEqual(len(password), 24)
        user.refresh_from_db()
        self.assertNotEqual(user.password, password)
        self.assertTrue(user.check_password(password))
        self.assertNotIn(password, str(user.__dict__))
        other, other_password = self.create("bob", "bob@example.org")
        self.assertNotEqual(password, other_password)

    def test_default_password_policy_and_explicit_override(self):
        for password in ["tiny", "x" * 129, "123456789123456789"]:
            with self.subTest(password=password), self.assertRaises(ValidationError):
                self.create(password=password)
        user, displayed = self.create(password="a teaching passphrase with spaces")
        self.assertIsNone(displayed)
        self.assertTrue(user.check_password("a teaching passphrase with spaces"))
        short, _ = self.create("bob", "bob@example.org", password="demo", allow_weak_password=True)
        self.assertTrue(short.check_password("demo"))
        with self.assertRaises(ValidationError):
            self.create("carol", "carol@example.org", password="", allow_weak_password=True)

    def test_identity_is_immutable_and_new_accounts_get_new_identity(self):
        user, _ = self.create()
        identity = user.identity
        user.username, user.email = "renamed", "renamed@example.org"
        user.save()
        self.assertEqual(user.identity, identity)
        user.identity = User().identity
        with self.assertRaises(ValidationError):
            user.save()
        user.refresh_from_db()
        user.delete()
        replacement, _ = self.create()
        self.assertNotEqual(replacement.identity, identity)

    def test_groups_never_grant_administration(self):
        user, _ = self.create(groups=["Administrators", "Students", "Students"])
        self.assertEqual(user.groups.count(), 2)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_last_active_admin_safeguard(self):
        first, _ = self.create(admin=True)
        for mutation in ["demote", "disable", "delete"]:
            with self.subTest(mutation=mutation), self.assertRaises(ValidationError):
                if mutation == "demote":
                    accounts.set_admin(first.username, False)
                elif mutation == "disable":
                    first.is_active = False
                    first.save()
                else:
                    first.delete()
            first.refresh_from_db()
        second, _ = self.create("bob", "bob@example.org", admin=True)
        accounts.set_admin(first.username, False)
        second.refresh_from_db()
        self.assertTrue(second.is_staff)
        with self.assertRaises(ValidationError):
            second.delete()
        first.delete()

    def test_login_and_password_replacement_invalidate_prior_sessions(self):
        user, password = self.create()
        first, second = Client(), Client()
        self.assertTrue(first.login(username="ALICE@EXAMPLE.ORG", password=password))
        self.assertTrue(second.login(username="alice", password=password))
        # A new client with the same cookie reads the persisted database session.
        restarted = Client()
        restarted.cookies = first.cookies.copy()
        self.assertEqual(restarted.get("/idp/login/").wsgi_request.user.pk, user.pk)
        accounts.replace_password("ALICE")
        for client in (first, second, restarted):
            self.assertFalse(client.get("/idp/login/").wsgi_request.user.is_authenticated)

    def test_builtin_admin_is_not_mounted(self):
        self.assertEqual(self.client.get("/admin/").status_code, 404)


class CommandTests(TestCase):
    def command(self, *args, **kwargs):
        output = io.StringIO()
        call_command(*args, stdout=output, **kwargs)
        return output.getvalue()

    def import_records(self, records):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.json"
            path.write_text(json.dumps(records), encoding="utf-8")
            return self.command("idp_import_users", str(path))

    def test_cli_bootstrap_needs_no_saml_keys(self):
        with self.settings(SAML_IDP_KEY="/missing/key", SAML_IDP_CERT="/missing/cert"):
            output = self.command("idp_user", "create", "ADMIN", "--email", "admin@example.org", "--admin")
        password = output.split("Generated password (shown once): ")[1].strip()
        user = User.objects.get(username="admin")
        self.assertTrue(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.check_password(password))
        with self.assertRaises(CommandError):
            self.command("idp_user", "set-admin", "admin", "--disable")
        self.command("idp_user", "create", "other", "--email", "other@example.org")
        self.command("idp_user", "set-admin", "OTHER", "--enable")
        self.command("idp_user", "set-admin", "admin", "--disable")
        self.assertFalse(User.objects.get(username="admin").is_staff)

    def test_stdin_password_policy_and_no_password_echo(self):
        with patch("sys.stdin", io.StringIO("tiny\n")), self.assertRaises(CommandError):
            self.command("idp_user", "create", "alice", "--email", "alice@example.org", "--password-stdin")
        self.assertFalse(User.objects.exists())
        with patch("sys.stdin", io.StringIO("tiny\n")):
            output = self.command("idp_user", "create", "alice", "--email", "alice@example.org",
                                  "--password-stdin", "--allow-weak-password")
        self.assertNotIn("tiny", output)
        self.assertTrue(User.objects.get().check_password("tiny"))
        with patch("sys.stdin", io.StringIO("  long passphrase with spaces  \n")):
            output = self.command("idp_user", "set-password", "alice", "--password-stdin")
        self.assertNotIn("long passphrase", output)
        self.assertTrue(User.objects.get().check_password("  long passphrase with spaces  "))
        with self.assertRaises(CommandError):
            self.command("idp_user", "set-password", "alice", "--allow-weak-password")
        with patch("sys.stdin", io.StringIO("")), self.assertRaises(CommandError):
            self.command("idp_user", "set-password", "alice", "--password-stdin")

    def test_cli_password_replacement(self):
        self.command("idp_user", "create", "alice", "--email", "alice@example.org")
        output = self.command("idp_user", "set-password", "alice")
        password = output.split("Generated password (shown once): ")[1].strip()
        self.assertTrue(User.objects.get().check_password(password))
        with self.assertRaises(CommandError):
            self.command("idp_user", "set-password", "missing")

    def test_legacy_json_maps_profiles_ignores_credentials_and_admin_flags(self):
        output = self.import_records([{
            "name": "Alice", "email": "ALICE@example.org", "given_name": "Alice",
            "surname": "Andersson", "common_name": "Alice Example",
            "eduPersonScopedAffiliation": "student@example.org", "groups": ["Administrators"],
            "password": "legacy-secret", "password_hash": "legacy-hash", "is_staff": True,
        }])
        user = User.objects.get()
        self.assertEqual((user.username, user.first_name, user.last_name, user.display_name),
                         ("alice", "Alice", "Andersson", "Alice Example"))
        self.assertEqual(user.scoped_affiliation, "student@example.org")
        self.assertEqual(list(user.groups.values_list("name", flat=True)), ["Administrators"])
        self.assertFalse(user.is_staff)
        self.assertFalse(user.check_password("legacy-secret"))
        self.assertNotIn("legacy-secret", output)
        self.assertNotIn("legacy-hash", output)
        password = output.split("shown once): ")[1].splitlines()[0]
        self.assertTrue(user.check_password(password))

    def test_whole_import_is_validated_before_writes(self):
        records = [{"name": "alice", "email": "alice@example.org", "groups": ["Students"]},
                   {"name": "bob", "email": "invalid"}]
        with self.assertRaises(CommandError):
            self.import_records(records)
        self.assertFalse(User.objects.exists())
        self.assertFalse(Group.objects.exists())

    def test_import_duplicates_and_existing_conflicts_are_atomic(self):
        for second in [{"name": "ALICE", "email": "other@example.org"},
                       {"name": "other", "email": "ALICE@example.org"},
                       {"name": "alice@example.org", "email": "other@example.org"}]:
            with self.subTest(second=second), self.assertRaises(CommandError):
                self.import_records([{"name": "alice", "email": "alice@example.org"}, second])
            self.assertFalse(User.objects.exists())
        accounts.create_user(username="existing", email="existing@example.org")
        with self.assertRaises(CommandError):
            self.import_records([{"name": "new", "email": "new@example.org"},
                                 {"name": "EXISTING", "email": "other@example.org"}])
        self.assertEqual(User.objects.count(), 1)

    def test_import_rolls_back_a_conflict_introduced_after_validation(self):
        prepared = prepare_import(json.dumps([
            {"name": "alice", "email": "alice@example.org", "groups": ["Students"]},
            {"name": "bob", "email": "bob@example.org"},
        ]))
        accounts.create_user(username="bob", email="bob@example.org")
        with self.assertRaises(ValidationError):
            accounts.commit_users(prepared)
        self.assertEqual(list(User.objects.values_list("username", flat=True)), ["bob"])
        self.assertFalse(Group.objects.exists())

    def test_invalid_json_shapes_and_groups(self):
        for records in [{}, [None], [{"name": "alice"}],
                        [{"name": "alice", "email": "alice@example.org", "groups": "Admins"}],
                        [{"name": "alice", "username": "bob", "email": "alice@example.org"}],
                        [{"name": 42, "email": "alice@example.org"}]]:
            with self.subTest(records=records), self.assertRaises(CommandError):
                self.import_records(records)
        self.assertFalse(User.objects.exists())
        self.import_records({"users": [{"username": "alice", "email": "alice@example.org"}]})
        self.assertEqual(User.objects.count(), 1)

    def test_opt_in_seed_uses_random_passwords_and_is_idempotent(self):
        self.assertFalse(User.objects.exists())
        output = self.command("seed_demo")
        self.assertEqual(User.objects.count(), 8)
        self.assertFalse(User.objects.filter(is_staff=True).exists())
        passwords = [line.split("shown once): ")[1] for line in output.splitlines() if "shown once" in line]
        self.assertEqual(len(set(passwords)), 8)
        self.assertTrue(all(len(password) == 24 for password in passwords))
        self.assertNotIn("shown once", self.command("seed_demo"))

    def test_seed_weak_password_override_is_explicit(self):
        with patch("sys.stdin", io.StringIO("lesson\n")):
            self.command("seed_demo", "--password-stdin", "--allow-weak-password")
        self.assertTrue(all(user.check_password("lesson") for user in User.objects.all()))


class ConcurrentAdministratorTests(TransactionTestCase):
    def test_competing_demotions_retain_one_administrator(self):
        if connections["default"].settings_dict["NAME"].startswith("file:memory"):
            self.skipTest("Use --settings=config.test_settings for SQLite writer-concurrency tests.")
        for username in ("alice", "bob"):
            accounts.create_user(username=username, email=f"{username}@example.org", admin=True)
        barrier = Barrier(2)

        def demote(username):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                accounts.set_admin(username, False)
                return "demoted"
            except ValidationError:
                return "protected"
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(demote, ("alice", "bob")))
        self.assertCountEqual(results, ["demoted", "protected"])
        self.assertEqual(User.objects.filter(is_active=True, is_staff=True).count(), 1)
