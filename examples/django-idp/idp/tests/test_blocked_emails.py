import io
import re
from contextlib import redirect_stdout
from unittest.mock import patch
from urllib.parse import urlsplit

from django.contrib.auth.forms import SetPasswordForm
from django.core import mail
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from idp.accounts import create_user
from idp.models import BlockedRecoveryEmail
from idp.recovery import RecoveryForm


class BlockedRecoveryEmailTests(TestCase):
    def setUp(self):
        self.admin, _ = create_user(username="operator", email="operator@example.org", admin=True)
        self.user, self.password = create_user(username="alice", email="alice@example.org")
        self.client.force_login(self.admin)
        self.url = reverse("idp_admin:blocked_emails")
        self.reset_url = reverse("idp:password_reset")
        self.block = BlockedRecoveryEmail.objects.create(email="alice@example.org")

    def remove_url(self):
        return reverse("idp_admin:blocked_email_remove", args=[self.block.pk])

    def test_admin_only_for_listing_adding_and_removing(self):
        for url in [self.url, self.remove_url()]:
            for method in ["get", "post"]:
                browser = Client()
                self.assertEqual(getattr(browser, method)(url).status_code, 302)
                browser.force_login(self.user)
                self.assertEqual(getattr(browser, method)(url).status_code, 403)
        self.assertContains(self.client.get(reverse("idp_admin:users")), self.url)
        response = self.client.get(self.url)
        self.assertContains(response, "alice@example.org")
        self.assertIn("no-store", response["Cache-Control"])

    def test_bulk_add_normalizes_deduplicates_and_survives_without_account(self):
        response = self.client.post(self.url, {
            "emails": " ALICE@EXAMPLE.ORG, future@example.org\nＦＵＴＵＲＥ@example.org\n other@example.org\n"})
        self.assertRedirects(response, self.url)
        self.assertEqual(list(BlockedRecoveryEmail.objects.values_list("email", flat=True)),
                         ["alice@example.org", "future@example.org", "other@example.org"])
        future, _ = create_user(username="future", email="future@example.org")
        with patch("django.core.mail.EmailMultiAlternatives.send") as send:
            response = Client().post(self.reset_url, {"email": future.email})
        self.assertRedirects(response, reverse("idp:password_reset_done"))
        send.assert_not_called()

    def test_invalid_bulk_add_is_atomic(self):
        for emails in ["valid@example.org\ninvalid", " , \n", "x" * 255 + "@example.org"]:
            with self.subTest(emails=emails):
                response = self.client.post(self.url, {"emails": emails})
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.context["form"].errors)
                self.assertEqual(BlockedRecoveryEmail.objects.count(), 1)

    def test_csrf_and_post_only_removal(self):
        browser = Client(enforce_csrf_checks=True)
        browser.force_login(self.admin)
        self.assertEqual(browser.post(self.url, {"emails": "other@example.org"}).status_code, 403)
        self.assertEqual(browser.post(self.remove_url()).status_code, 403)
        self.assertEqual(self.client.get(self.remove_url()).status_code, 405)
        self.assertTrue(BlockedRecoveryEmail.objects.filter(pk=self.block.pk).exists())

    def test_remove_reenables_recovery(self):
        self.assertRedirects(self.client.post(self.remove_url()), self.url)
        self.assertFalse(BlockedRecoveryEmail.objects.exists())
        response = Client().post(self.reset_url, {"email": self.user.email})
        self.assertRedirects(response, reverse("idp:password_reset_done"))
        self.assertEqual(len(mail.outbox), 1)

    def test_blocked_recipient_gets_generic_response_without_any_delivery(self):
        browser = Client()
        with patch("django.core.mail.EmailMultiAlternatives.send") as send:
            response = browser.post(self.reset_url, {"email": "ALICE@EXAMPLE.ORG"})
        self.assertRedirects(response, reverse("idp:password_reset_done"))
        send.assert_not_called()
        self.assertContains(browser.get(response.url), "If an eligible account")
        # Manual account creation/replacement and normal login remain available.
        self.assertTrue(browser.login(username=self.user.username, password=self.password))

    @override_settings(MAILERS={"default": {"BACKEND": "django.core.mail.backends.console.EmailBackend"}})
    def test_blocked_recipient_has_no_console_reset_link(self):
        output = io.StringIO()
        with redirect_stdout(output):
            response = Client().post(self.reset_url, {"email": self.user.email})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(output.getvalue(), "")

    def test_delivery_rechecks_if_address_blocked_after_user_lookup(self):
        self.block.delete()
        form = RecoveryForm({"email": self.user.email})
        self.assertTrue(form.is_valid())
        original = RecoveryForm.get_users

        def users(form, email):
            matches = list(original(form, email))
            BlockedRecoveryEmail.objects.create(email=email)
            return matches

        with patch.object(RecoveryForm, "get_users", users):
            with patch("django.core.mail.EmailMultiAlternatives.send") as send:
                form.save(domain_override="IdP",
                          email_template_name="idp/password_reset_email.txt",
                          subject_template_name="idp/password_reset_subject.txt")
        send.assert_not_called()

    def test_existing_link_is_disabled_when_email_is_blocked(self):
        self.block.delete()
        browser = Client()
        browser.post(self.reset_url, {"email": self.user.email})
        path = urlsplit(re.search(r'http://\S+', mail.outbox[-1].body).group()).path
        confirm = browser.get(path).url
        self.block = BlockedRecoveryEmail.objects.create(email=self.user.email)
        self.assertContains(browser.get(path), "invalid or has expired")
        self.assertContains(browser.post(confirm, {
            "new_password1": "a recovered teaching passphrase",
            "new_password2": "a recovered teaching passphrase"}), "invalid or has expired")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))

    def test_block_added_during_hashing_prevents_completion(self):
        self.block.delete()
        browser = Client()
        browser.post(self.reset_url, {"email": self.user.email})
        path = urlsplit(re.search(r'http://\S+', mail.outbox[-1].body).group()).path
        confirm = browser.get(path).url
        original = SetPasswordForm.save

        def save(form, commit=True):
            BlockedRecoveryEmail.objects.create(email=self.user.email)
            return original(form, commit=commit)

        with patch.object(SetPasswordForm, "save", save):
            response = browser.post(confirm, {"new_password1": "a recovered teaching passphrase",
                                              "new_password2": "a recovered teaching passphrase"})
        self.assertContains(response, "invalid or has expired")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))

    def test_write_rechecks_administrator(self):
        from idp.admin_views import check_administrator

        def demote(request):
            # A separate demotion has landed since the request was authenticated.
            type(self.admin).objects.filter(pk=self.admin.pk).update(is_staff=False)
            check_administrator(request)

        for url, data in [(self.url, {"emails": "other@example.org"}), (self.remove_url(), {})]:
            with patch("idp.admin_views.check_administrator", side_effect=demote):
                self.assertEqual(self.client.post(url, data).status_code, 403)
            self.assertTrue(BlockedRecoveryEmail.objects.filter(pk=self.block.pk).exists())
            self.assertEqual(BlockedRecoveryEmail.objects.count(), 1)
