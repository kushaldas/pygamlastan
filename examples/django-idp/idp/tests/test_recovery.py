import io
import os
import re
import runpy
import tempfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path
from threading import Barrier
from unittest.mock import patch
from urllib.parse import urlsplit

from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.db import close_old_connections, connections
from django.test import Client, RequestFactory, TestCase, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from idp.accounts import create_user, replace_password
from idp.models import RecoveryRateLimit
from idp.recovery import client_ip, consume_limits


@override_settings(SAML_IDP_BASE_URL="https://idp.example.org")
class RecoveryTests(TestCase):
    def setUp(self):
        self.user, self.password = create_user(username="alice", email="alice@example.org")
        self.url = reverse("idp:password_reset")
        self.new_password = "a recovered teaching passphrase"

    def request_reset(self, email="alice@example.org", **kwargs):
        return self.client.post(self.url, {"email": email}, **kwargs)

    def reset_path(self):
        self.request_reset()
        return urlsplit(re.search(r'https://\S+', mail.outbox[-1].body).group()).path

    def open_link(self, path, browser=None):
        browser = browser or self.client
        response = browser.get(path)
        self.assertEqual(response.status_code, 302)
        self.assertIn("set-password", response.url)
        return response.url

    def complete(self, path, browser=None, **data):
        return (browser or self.client).post(path, {
            "new_password1": self.new_password, "new_password2": self.new_password, **data})

    def test_login_link_and_generic_responses(self):
        self.assertContains(self.client.get("/idp/login/"), 'href="/idp/password-reset/"')
        other, _ = create_user(username="disabled", email="disabled@example.org", is_active=False)
        other.set_unusable_password()
        other.save()
        for email in ["alice@example.org", "missing@example.org", "disabled@example.org"]:
            response = self.request_reset(email)
            self.assertRedirects(response, reverse("idp:password_reset_done"))
        self.assertEqual(len(mail.outbox), 1)
        self.assertContains(self.client.get(reverse("idp:password_reset_done")), "If an eligible account")

    def test_link_uses_configured_origin_and_normalized_email(self):
        response = self.request_reset("ALICE@EXAMPLE.ORG", HTTP_HOST="untrusted.example")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(mail.outbox[0].to, [self.user.email])
        self.assertIn("https://idp.example.org/idp/password-reset/", mail.outbox[0].body)
        self.assertNotIn("untrusted.example", mail.outbox[0].body)
        self.assertNotIn(self.password, mail.outbox[0].body)

    def test_reset_requires_post_invalidates_sessions_and_token_reuse(self):
        browsers = [Client(), Client()]
        for browser in browsers:
            browser.force_login(self.user)
        path = self.reset_path()
        confirm = self.open_link(path)
        self.assertContains(self.client.get(confirm), "Set new password")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))
        # Another browser can open the same link before it is used.
        other = Client()
        other_confirm = self.open_link(path, other)
        response = self.complete(confirm)
        self.assertRedirects(response, reverse("idp:password_reset_complete"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))
        self.assertFalse(self.user.check_password(self.password))
        for browser in browsers:
            self.assertEqual(browser.get("/idp/profile/").status_code, 302)
        self.assertEqual(self.client.get("/idp/profile/").status_code, 302)
        self.assertContains(other.get(path), "invalid or has expired")
        self.assertContains(self.complete(other_confirm, other), "invalid or has expired")

    def test_invalid_expired_and_disabled_tokens(self):
        path = self.reset_path()
        self.assertContains(self.client.get(path.rstrip("/") + "bad/"), "invalid or has expired")
        future = datetime.now() + timedelta(seconds=3601)
        with patch.object(default_token_generator, "_now", return_value=future):
            self.assertContains(self.client.get(path), "invalid or has expired")
        confirm = self.open_link(path)
        self.user.is_active = False
        self.user.save()
        self.assertContains(self.client.get(path), "invalid or has expired")
        self.assertContains(self.complete(confirm), "invalid or has expired")

    def test_weak_or_mismatched_password_does_not_consume_token(self):
        path = self.reset_path()
        confirm = self.open_link(path)
        for data in [{"new_password2": "different"},
                     {"new_password1": "tiny", "new_password2": "tiny"}]:
            response = self.complete(confirm, **data)
            self.assertTrue(response.context["form"].errors)
        self.assertEqual(self.complete(confirm).status_code, 302)

    def test_concurrent_replacement_during_hashing_is_not_overwritten(self):
        confirm = self.open_link(self.reset_path())
        original = SetPasswordForm.save

        def save(form, commit=True):
            replace_password("alice", password="an administrative replacement passphrase")
            return original(form, commit=commit)

        with patch.object(SetPasswordForm, "save", save):
            self.assertContains(self.complete(confirm), "invalid or has expired")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("an administrative replacement passphrase"))

    def test_deactivation_during_hashing_is_not_overwritten(self):
        confirm = self.open_link(self.reset_path())
        original = SetPasswordForm.save

        def save(form, commit=True):
            self.user.is_active = False
            self.user.save()
            return original(form, commit=commit)

        with patch.object(SetPasswordForm, "save", save):
            self.assertContains(self.complete(confirm), "invalid or has expired")
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertTrue(self.user.check_password(self.password))

    def test_csrf_and_no_cache(self):
        browser = Client(enforce_csrf_checks=True)
        self.assertEqual(browser.post(self.url, {"email": self.user.email}).status_code, 403)
        confirm = self.open_link(self.reset_path(), browser)
        self.assertEqual(self.complete(confirm, browser).status_code, 403)
        for url in [self.url, confirm, reverse("idp:password_reset_done"),
                    reverse("idp:password_reset_complete")]:
            self.assertIn("no-store", self.client.get(url)["Cache-Control"])
        self.assertEqual(self.client.put(self.url).status_code, 405)

    @override_settings(SAML_IDP_RESET_EMAIL_LIMIT=2)
    def test_email_limit_across_ips_and_sessions(self):
        for n in range(3):
            browser = Client()
            response = browser.post(self.url, {"email": "ALICE@EXAMPLE.ORG"}, REMOTE_ADDR=f"192.0.2.{n}")
            self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 2)
        stored = str(list(RecoveryRateLimit.objects.values()))
        self.assertNotIn("alice@example.org", stored)
        self.assertNotIn("192.0.2.", stored)

    @override_settings(SAML_IDP_RESET_IP_LIMIT=2)
    def test_ip_limit_across_addresses_ignores_spoofed_forwarding_and_expires(self):
        for n in range(2):
            self.assertEqual(self.request_reset(f"unknown{n}@example.org").status_code, 302)
        response = self.request_reset(HTTP_X_FORWARDED_FOR="198.51.100.123")
        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response["Retry-After"]), 0)
        self.assertEqual(len(mail.outbox), 0)
        buckets = RecoveryRateLimit.objects.count()
        self.assertEqual(self.request_reset("another@example.org").status_code, 429)
        self.assertEqual(RecoveryRateLimit.objects.count(), buckets)
        with patch("idp.recovery.timezone.now", return_value=timezone.now() + timedelta(seconds=901)):
            self.assertEqual(self.request_reset().status_code, 302)
        self.assertEqual(len(mail.outbox), 1)

    @override_settings(SAML_IDP_RESET_CONFIRM_LIMIT=2)
    def test_confirmation_posts_are_rate_limited(self):
        confirm = self.open_link(self.reset_path())
        for _ in range(2):
            self.assertEqual(self.complete(confirm, new_password2="wrong").status_code, 200)
        response = self.complete(confirm)
        self.assertEqual(response.status_code, 429)
        self.assertIn("no-store", response["Cache-Control"])
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))

    @override_settings(MAILERS={"default": {"BACKEND": "django.core.mail.backends.console.EmailBackend"}})
    def test_unconfigured_mail_can_be_written_to_console(self):
        output = io.StringIO()
        with redirect_stdout(output):
            response = self.request_reset()
        self.assertEqual(response.status_code, 302)
        self.assertIn("https://idp.example.org/idp/password-reset/", output.getvalue())
        self.assertNotIn("https://idp.example.org/idp/password-reset/", response.content.decode())

    def test_smtp_failure_does_not_fall_back_to_console(self):
        output = io.StringIO()
        with patch("django.core.mail.EmailMultiAlternatives.send", side_effect=OSError("SMTP unavailable")):
            with redirect_stdout(output), self.assertLogs("django.contrib.auth", level="ERROR"):
                self.assertEqual(self.request_reset().status_code, 302)
        self.assertEqual(output.getvalue(), "")

    @override_settings(MAILERS={"default": {
        "BACKEND": "django.core.mail.backends.smtp.EmailBackend",
        "OPTIONS": {"host": "smtp.gmail.com", "port": 587, "use_tls": True,
                    "username": "sender@gmail.com", "password": "app-password", "timeout": 15},
    }})
    def test_configured_smtp_uses_starttls_and_authentication(self):
        with patch("smtplib.SMTP") as smtp:
            self.assertEqual(self.request_reset().status_code, 302)
        smtp.assert_called_once()
        self.assertEqual(smtp.call_args.args[:2], ("smtp.gmail.com", 587))
        smtp.return_value.starttls.assert_called_once()
        smtp.return_value.login.assert_called_once_with("sender@gmail.com", "app-password")
        smtp.return_value.sendmail.assert_called_once()

    @override_settings(SAML_IDP_TRUSTED_PROXIES=["10.0.0.0/24"])
    def test_trusted_proxy_hops(self):
        request = RequestFactory().get("/", REMOTE_ADDR="10.0.0.1",
                                       HTTP_X_FORWARDED_FOR="192.0.2.10, 198.51.100.2, 10.0.0.2")
        self.assertEqual(client_ip(request), "198.51.100.2")
        request.META["REMOTE_ADDR"] = "203.0.113.1"
        self.assertEqual(client_ip(request), "203.0.113.1")

    def test_mail_configuration_defaults_and_smtp_options(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {"SAML_IDP_DATA_DIR": directory}
            with patch.dict(os.environ, env, clear=True):
                config = runpy.run_path(str(Path(__file__).resolve().parents[2] / "config/settings.py"))
            self.assertEqual(config["MAILERS"]["default"]["BACKEND"], "django.core.mail.backends.console.EmailBackend")
            env.update(EMAIL_HOST_USER="sender@gmail.com", EMAIL_HOST_PASSWORD="app-password")
            with patch.dict(os.environ, env, clear=True):
                config = runpy.run_path(str(Path(__file__).resolve().parents[2] / "config/settings.py"))
            options = config["MAILERS"]["default"]["OPTIONS"]
            self.assertEqual(options["host"], "smtp.gmail.com")
            self.assertEqual(options["password"], "app-password")
            self.assertTrue(options["use_tls"])
            self.assertEqual(options["port"], 587)
            self.assertEqual(config["DEFAULT_FROM_EMAIL"], "sender@gmail.com")


class ConcurrentRecoveryTests(TransactionTestCase):
    def test_competing_reset_completions_only_accept_one_password(self):
        user, _ = create_user(username="alice", email="alice@example.org")
        self.client.post(reverse("idp:password_reset"), {"email": user.email})
        path = urlsplit(re.search(r'http://\S+', mail.outbox[-1].body).group()).path
        browsers = [Client(), Client()]
        paths = [browser.get(path).url for browser in browsers]
        barrier = Barrier(2)
        original = SetPasswordForm.save

        def save(form, commit=True):
            prepared = original(form, commit=commit)
            barrier.wait(timeout=10)
            return prepared

        def complete(index):
            close_old_connections()
            try:
                password = f"a recovered passphrase number {index}"
                return browsers[index].post(paths[index], {
                    "new_password1": password, "new_password2": password}).status_code
            finally:
                connections.close_all()

        with patch.object(SetPasswordForm, "save", save):
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(complete, range(2)))
        self.assertCountEqual(results, [200, 302])
        user.refresh_from_db()
        self.assertTrue(user.check_password(f"a recovered passphrase number {results.index(302)}"))

    def test_workers_share_a_single_quota(self):
        barrier = Barrier(2)

        def consume(_):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                return bool(consume_limits([("request-ip", "192.0.2.1", 1, 900)]))
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(consume, range(2)))
        self.assertCountEqual(results, [False, True])
        self.assertEqual(RecoveryRateLimit.objects.get().count, 1)
