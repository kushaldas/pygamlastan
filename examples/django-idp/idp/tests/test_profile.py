from unittest.mock import patch

from django.contrib.sessions.models import Session
from django.test import Client, TestCase
from django.utils import timezone
from datetime import timedelta

from idp.accounts import create_user, replace_password
from idp.models import SamlParticipant


class ProfileTests(TestCase):
    def setUp(self):
        self.user, self.password = create_user(username="alice", email="alice@example.org")
        self.browser = Client()
        self.browser.login(username="alice", password=self.password)
        self.new_password = "my new teaching passphrase"

    def payload(self, **overrides):
        return {"old_password": self.password, "new_password1": self.new_password,
                "new_password2": self.new_password, **overrides}

    def test_profile_requires_login_and_shows_read_only_account_details(self):
        self.assertRedirects(Client().get("/idp/profile/"), "/idp/login/?next=/idp/profile/", fetch_redirect_response=False)
        self.assertRedirects(Client().post("/idp/profile/", self.payload()), "/idp/login/?next=/idp/profile/", fetch_redirect_response=False)
        response = self.browser.get("/idp/profile/")
        self.assertContains(response, "Your profile")
        self.assertContains(response, "alice@example.org")
        self.assertContains(response, 'name="old_password"')
        self.assertContains(response, 'name="new_password1"')
        self.assertNotContains(response, 'name="email"')
        self.assertIn("no-store", response["Cache-Control"])

    def test_regular_login_lands_on_profile(self):
        response = Client().post("/idp/login/", {"username": "ALICE@EXAMPLE.ORG", "password": self.password})
        self.assertRedirects(response, "/idp/profile/", fetch_redirect_response=False)

    def test_password_change_rotates_current_session_invalidates_others_and_preserves_slo(self):
        other = Client()
        other.login(username="alice", password=self.password)
        old_key = self.browser.session.session_key
        participant = SamlParticipant.objects.create(
            session_key=old_key, entity_id="https://sp.example.org", name_id={"value": "opaque"},
            session_index="_session", expires_at=timezone.now() + timedelta(hours=1),
        )
        response = self.browser.post("/idp/profile/", self.payload(), follow=True)
        self.assertContains(response, "Your password has been changed.")
        new_key = self.browser.session.session_key
        self.assertNotEqual(new_key, old_key)
        self.assertFalse(Session.objects.filter(pk=old_key).exists())
        self.assertEqual(response.wsgi_request.user.pk, self.user.pk)
        self.assertFalse(other.get("/idp/login/").wsgi_request.user.is_authenticated)
        participant.refresh_from_db()
        self.assertEqual(participant.session_key, new_key)
        self.assertAlmostEqual(participant.expires_at.timestamp(), Session.objects.get(pk=new_key).expire_date.timestamp(), delta=1)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))
        self.assertFalse(self.user.check_password(self.password))
        self.assertNotIn(self.new_password, str(self.browser.session.items()))
        self.assertNotContains(response, self.new_password)

    def test_wrong_current_password_mismatch_and_weak_passwords_are_rejected(self):
        for overrides in ({"old_password": "wrong"}, {"new_password2": "different"},
                          {"new_password1": "short", "new_password2": "short"},
                          {"new_password1": "123456789123456789", "new_password2": "123456789123456789"},
                          {"new_password1": "x" * 129, "new_password2": "x" * 129}):
            with self.subTest(overrides=overrides):
                response = self.browser.post("/idp/profile/", self.payload(**overrides))
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.context["form"].errors)
                self.user.refresh_from_db()
                self.assertTrue(self.user.check_password(self.password))

    def test_csrf_is_required(self):
        browser = Client(enforce_csrf_checks=True)
        browser.cookies = self.browser.cookies.copy()
        self.assertEqual(browser.post("/idp/profile/", self.payload()).status_code, 403)

    def test_password_change_only_affects_current_user(self):
        bob, password = create_user(username="bob", email="bob@example.org")
        self.browser.post("/idp/profile/", self.payload(username="bob", email="edited@example.org", is_staff="on"))
        self.user.refresh_from_db()
        bob.refresh_from_db()
        self.assertEqual(self.user.email, "alice@example.org")
        self.assertFalse(self.user.is_staff)
        self.assertTrue(bob.check_password(password))

    def test_concurrent_administrative_password_replacement_is_not_overwritten(self):
        from django.contrib.auth.forms import PasswordChangeForm
        original = PasswordChangeForm.save

        def save(form, commit=True):
            replace_password("alice", password="a newer administrative password")
            return original(form, commit=commit)

        with patch.object(PasswordChangeForm, "save", save):
            response = self.browser.post("/idp/profile/", self.payload())
        self.assertContains(response, "Your account changed. Please try again.")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("a newer administrative password"))
