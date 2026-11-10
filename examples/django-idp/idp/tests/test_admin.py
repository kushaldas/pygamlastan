"""Account administration authorization, validation, and Unicode search regressions."""
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.db import connection
from django.test import Client, TestCase, TransactionTestCase
from django.urls import reverse

from idp.accounts import create_user
from idp.admin_forms import AccountForm
from idp.models import User


class AdminTests(TestCase):
    """Exercise staff-only account actions and their account-model invariants."""
    def setUp(self):
        """Create isolated accounts and an authenticated administrator for each test."""
        self.admin, self.admin_password = create_user(
            username="operator", email="operator@example.org", admin=True)
        self.account, self.password = create_user(username="alice", email="alice@example.org")
        self.client.force_login(self.admin)
        self.home = reverse("idp_admin:users")

    def url(self, action, account=None):
        """Build an administrative action URL for the selected or default test account."""
        return reverse("idp_admin:user_" + action, args=[(account or self.account).pk])

    def payload(self, **overrides):
        """Provide valid account edits with explicit overrides for each regression case."""
        return {"username": self.account.username, "email": self.account.email,
                "is_active": "on", "group_names": "Students, Teachers", **overrides}

    def test_all_endpoints_require_staff_and_active_accounts(self):
        """Reject anonymous, ordinary, and disabled users on every account admin route."""
        urls = [self.home, reverse("idp_admin:user_create"), self.url("edit"),
                self.url("reset"), self.url("delete")]
        for url in urls:
            with self.subTest(url=url):
                self.assertEqual(Client().get(url).status_code, 302)
                self.assertEqual(Client().post(url).status_code, 302)
                ordinary = Client()
                ordinary.force_login(self.account)
                self.assertEqual(ordinary.get(url).status_code, 403)
                self.assertEqual(ordinary.post(url).status_code, 403)
        create_user(username="backup", email="backup@example.org", admin=True)
        self.admin.is_active = False
        self.admin.save()
        self.assertEqual(self.client.get(self.home).status_code, 302)

    def test_list_search_pagination_and_no_cache(self):
        """Keep account search paginated and administrative responses uncached."""
        response = self.client.get(self.home, {"q": "ALICE"})
        self.assertContains(response, "alice@example.org")
        self.assertNotContains(response, "operator@example.org")
        self.assertIn("no-store", response["Cache-Control"])
        User.objects.bulk_create([
            User(username=f"student{i:02}", email=f"s{i}@example.org") for i in range(52)])
        response = self.client.get(self.home, {"q": "student", "page": "2"})
        self.assertEqual(len(response.context["page"]), 2)
        self.assertContains(response, "Page 2 of 2")

    def test_identifier_search_normalizes_unicode_without_changing_display_search(self):
        """Match Unicode identifier variants and retain literal display-name searches."""
        account, _ = create_user(username="Åsa", email="asa@åsa.example", display_name="ＡＢＣ")
        for query in ["ÅSA", "ASA@ÅSA.EXAMPLE", "ＡLICE"]:
            response = self.client.get(self.home, {"q": query})
            expected = self.account if query == "ＡLICE" else account
            self.assertEqual(list(response.context["page"]), [expected])
            self.assertEqual(response.context["query"], query)
        response = self.client.get(self.home, {"q": "ＡＢＣ"})
        self.assertEqual(list(response.context["page"]), [account])

    def test_create_password_shown_once_without_plaintext_storage(self):
        """Show generated credentials only in the creation response, never stored state."""
        response = self.client.post(reverse("idp_admin:user_create"), self.payload(
            username="BOB", email="BOB@example.org", group_names="Students, Students"))
        self.assertEqual(response.status_code, 200)
        bob = User.objects.get(username="bob")
        password = response.context["password"]
        self.assertEqual(len(password), 24)
        self.assertTrue(bob.check_password(password))
        self.assertEqual(list(bob.groups.values_list("name", flat=True)), ["Students"])
        self.assertFalse(bob.is_staff)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertNotIn(password, str(self.client.session.items()))
        self.assertNotIn(password, str(list(response.context["messages"])))
        self.assertNotContains(self.client.get(self.url("edit", bob)), password)
        self.assertNotContains(self.client.get(self.home), password)

    def test_edit_allowlist_and_groups_do_not_grant_admin(self):
        """Keep unlisted privileges and identity fields unchanged during profile edits."""
        response = self.client.post(self.url("edit"), self.payload(
            username="Renamed", display_name="Alice Example", group_names="Administrators",
            is_superuser="on", password="injected", identity="00000000-0000-0000-0000-000000000000"))
        self.assertRedirects(response, self.home)
        identity = self.account.identity
        self.account.refresh_from_db()
        self.assertEqual(self.account.username, "renamed")
        self.assertEqual(self.account.identity, identity)
        self.assertEqual(self.account.display_name, "Alice Example")
        self.assertFalse(self.account.is_superuser)
        self.assertFalse(self.account.is_staff)
        self.assertTrue(self.account.check_password(self.password))
        self.assertTrue(self.account.groups.filter(name="Administrators").exists())

    def test_unchanged_edit_preserves_quoted_group_names(self):
        """Keep commas, quotes, spaces, and newlines intact when only a profile field changes."""
        names = ['cn=staff,ou=groups', 'He said "hello"', ' padded ', 'multi\nline']
        self.account.groups.set([Group.objects.create(name=name) for name in names])
        initial = self.client.get(self.url("edit")).context["form"]["group_names"].value()
        response = self.client.post(self.url("edit"), self.payload(
            display_name="Updated display name", group_names=initial))
        self.assertRedirects(response, self.home)
        self.assertCountEqual(self.account.groups.values_list("name", flat=True), names)
        self.assertEqual(Group.objects.count(), len(names))

    def test_group_csv_quotes_deduplicates_and_rejects_malformed_records(self):
        """Parse quoted CSV names once and reject ambiguous or incomplete records before saving."""
        form = AccountForm(self.payload(group_names='Students, "cn=staff,ou=groups", Students'),
                           instance=self.account)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["group_names"], ["Students", "cn=staff,ou=groups"])
        for value in ['"unclosed', 'Students\nTeachers']:
            response = self.client.post(self.url("edit"), self.payload(group_names=value))
            self.assertIn("group_names", response.context["form"].errors)
        self.assertFalse(self.account.groups.exists())

    def test_duplicates_and_invalid_groups_do_not_partially_write(self):
        """Reject all account and group changes when any submitted field is invalid."""
        for overrides in [{"email": self.admin.email}, {"username": self.admin.email},
                          {"group_names": "x" * 151}]:
            with self.subTest(overrides=overrides):
                response = self.client.post(self.url("edit"), self.payload(**overrides))
                self.assertTrue(response.context["form"].errors)
                self.account.refresh_from_db()
                self.assertEqual(self.account.username, "alice")
                self.assertEqual(self.account.email, "alice@example.org")
                self.assertFalse(Group.objects.exists())

    def test_promote_disable_and_demote(self):
        """Allow administrators to change another account role and active status."""
        self.client.post(self.url("edit"), self.payload(is_staff="on"))
        self.account.refresh_from_db()
        self.assertTrue(self.account.is_staff)
        self.client.post(self.url("edit"), self.payload(is_active=""))
        self.account.refresh_from_db()
        self.assertFalse(self.account.is_staff)
        self.assertFalse(self.account.is_active)

    def test_final_admin_cannot_be_demoted_disabled_or_deleted(self):
        """Retain at least one active administrator across destructive account actions."""
        url = self.url("edit", self.admin)
        for flags in [{"is_active": "on"}, {"is_staff": "on"}]:
            response = self.client.post(url, {
                "username": self.admin.username, "email": self.admin.email, **flags})
            self.assertContains(response, "final active administrator")
            self.admin.refresh_from_db()
            self.assertTrue(self.admin.is_active and self.admin.is_staff)
        response = self.client.post(self.url("delete", self.admin))
        self.assertContains(response, "final active administrator")
        self.assertTrue(User.objects.filter(pk=self.admin.pk).exists())

    def test_confirmations_are_read_only_and_reset_invalidates_old_sessions(self):
        """Require POST for mutations and reject sessions after password replacement."""
        browser = Client()
        browser.force_login(self.account)
        for action in ["reset", "delete"]:
            self.assertEqual(self.client.get(self.url(action)).status_code, 200)
            self.account.refresh_from_db()
            self.assertTrue(self.account.check_password(self.password))
        response = self.client.post(self.url("reset"))
        self.account.refresh_from_db()
        self.assertTrue(self.account.check_password(response.context["password"]))
        self.assertFalse(self.account.check_password(self.password))
        self.assertEqual(browser.get("/idp/profile/").status_code, 302)
        self.assertRedirects(self.client.post(self.url("delete")), self.home)
        self.assertFalse(User.objects.filter(pk=self.account.pk).exists())

    def test_csrf_is_required_for_all_writes(self):
        """Reject administrative mutations without a valid CSRF token."""
        browser = Client(enforce_csrf_checks=True)
        browser.force_login(self.admin)
        for url in [reverse("idp_admin:user_create"), self.url("edit"),
                    self.url("reset"), self.url("delete")]:
            self.assertEqual(browser.post(url, self.payload()).status_code, 403)

    def test_login_returns_to_admin_and_rejects_external_next(self):
        """Honor local login return paths without allowing external redirects."""
        for next_url, expected in [(self.home, self.home),
                                   ("?tab=accounts", "?tab=accounts"),
                                   ("profile", "profile"),
                                   ("https://evil.example/", "/idp/profile/")]:
            browser = Client()
            response = browser.post("/idp/login/", {
                "username": self.admin.username, "password": self.admin_password},
                QUERY_STRING="next=" + next_url)
            # Query-only and relative targets are URL references, not Django URL
            # names; inspect Location without following a deliberately relative URL.
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response["Location"], expected)

    def test_write_rechecks_privileges(self):
        # Simulate a demotion between the request's initial check and mutation.
        """Reject writes after administrator privileges change during the request."""
        from idp.admin_views import check_administrator

        def demote(request):
            """Simulate privilege revocation between authentication and the write check."""
            User.objects.filter(pk=self.admin.pk).update(is_staff=False)
            check_administrator(request)

        with patch("idp.admin_views.check_administrator", side_effect=demote):
            response = self.client.post(self.url("delete"))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(User.objects.filter(pk=self.account.pk).exists())


class AdminCredentialPreparationTests(TransactionTestCase):
    """Keep expensive credential preparation outside SQLite write transactions."""

    def setUp(self):
        """Create real committed accounts so transaction assertions reflect HTTP behavior."""
        self.admin, _ = create_user(username="operator", email="operator@example.org", admin=True)
        self.account, _ = create_user(username="alice", email="alice@example.org")
        self.client.force_login(self.admin)

    def test_creation_and_password_replacement_hash_without_a_write_transaction(self):
        """Prepare each credential once before authorization and model writes take the lock."""
        original = User.set_password
        hashed = []

        def set_password(user, password):
            """Assert the real hasher runs without an encompassing database transaction."""
            self.assertFalse(connection.in_atomic_block)
            hashed.append(user.pk)
            return original(user, password)

        with patch.object(User, "set_password", set_password):
            created = self.client.post(reverse("idp_admin:user_create"), {
                "username": "bob", "email": "bob@example.org", "is_active": "on"})
            reset = self.client.post(reverse("idp_admin:user_reset", args=[self.account.pk]))
        self.assertEqual(created.status_code, 200)
        self.assertEqual(reset.status_code, 200)
        self.assertEqual(hashed, [None, self.account.pk])
        self.assertTrue(User.objects.get(username="bob").check_password(created.context["password"]))
        self.account.refresh_from_db()
        self.assertTrue(self.account.check_password(reset.context["password"]))

    def test_password_replacement_reloads_profile_changes_after_hashing(self):
        """Commit the prepared hash to the same account without overwriting newer profile fields."""
        original = User.set_password

        def set_password(user, password):
            """Simulate a committed profile rename during credential preparation."""
            result = original(user, password)
            User.objects.filter(pk=user.pk).update(username="renamed", display_name="Concurrent edit")
            return result

        with patch.object(User, "set_password", set_password):
            response = self.client.post(reverse("idp_admin:user_reset", args=[self.account.pk]))
        self.assertEqual(response.status_code, 200)
        self.account.refresh_from_db()
        self.assertEqual(self.account.username, "renamed")
        self.assertEqual(self.account.display_name, "Concurrent edit")
        self.assertTrue(self.account.check_password(response.context["password"]))

    def test_creation_rechecks_privileges_after_hashing(self):
        """Reject account creation when its administrator is demoted during hashing."""
        create_user(username="backup", email="backup@example.org", admin=True)
        original = User.set_password

        def set_password(user, password):
            """Commit administrator revocation after preparing the new credential."""
            result = original(user, password)
            administrator = User.objects.get(pk=self.admin.pk)
            administrator.is_staff = False
            administrator.save(update_fields=["is_staff"])
            return result

        with patch.object(User, "set_password", set_password):
            response = self.client.post(reverse("idp_admin:user_create"), {
                "username": "bob", "email": "bob@example.org", "is_active": "on"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(User.objects.filter(username="bob").exists())
        self.admin.refresh_from_db()
        self.assertFalse(self.admin.is_staff)

    def test_password_replacement_rechecks_privileges_after_hashing(self):
        """Keep the target password unchanged if the acting administrator loses access."""
        create_user(username="backup", email="backup@example.org", admin=True)
        old_hash = self.account.password
        original = User.set_password

        def set_password(user, password):
            """Revoke the acting role while the replacement password is being prepared."""
            result = original(user, password)
            administrator = User.objects.get(pk=self.admin.pk)
            administrator.is_staff = False
            administrator.save(update_fields=["is_staff"])
            return result

        with patch.object(User, "set_password", set_password):
            response = self.client.post(reverse("idp_admin:user_reset", args=[self.account.pk]))
        self.assertEqual(response.status_code, 403)
        self.account.refresh_from_db()
        self.assertEqual(self.account.password, old_hash)

    def test_creation_revalidates_conflicts_introduced_during_hashing(self):
        """Reject a late identifier conflict without displaying or persisting the prepared credential."""
        from idp.admin_views import prepare_user

        def prepare_with_conflict(**kwargs):
            """Commit a competing account after preparation but before the admin write lock."""
            prepared = prepare_user(**kwargs)
            create_user(username="bob", email="competing@example.org")
            return prepared

        with patch("idp.admin_views.prepare_user", side_effect=prepare_with_conflict):
            response = self.client.post(reverse("idp_admin:user_create"), {
                "username": "bob", "email": "bob@example.org", "is_active": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["form"].errors)
        with self.assertRaises(KeyError):
            response.context["password"]
        self.assertEqual(User.objects.get(username="bob").email, "competing@example.org")
        self.assertFalse(User.objects.filter(email="bob@example.org").exists())
