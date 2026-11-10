"""Account administration authorization, validation, and Unicode search regressions."""
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import Client, TestCase
from django.urls import reverse

from idp.accounts import create_user
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
                                   ("https://evil.example/", "/idp/profile/")]:
            browser = Client()
            response = browser.post("/idp/login/", {
                "username": self.admin.username, "password": self.admin_password},
                QUERY_STRING="next=" + next_url)
            self.assertRedirects(response, expected)

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
