"""Exercise the actual IdP and sibling SP views using real signed messages."""
from urllib.parse import urlsplit
from unittest.mock import patch

from django.test import Client, TestCase
from pygamlastan import bindings, core, logout as saml_logout, metadata, profiles

from idp.accounts import create_user
from idp import saml_logic as idp_logic
from idp.models import LogoutFlow, SamlParticipant
from idp.tests.saml_helpers import FormParser, decoded_response, deliver, make_config
from sp import saml_logic as sp_logic
from sp.models import LogoutTransaction, SamlLogin


class BrowserLogoutIntegrationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.idp = make_config("https://idp.example.org")
        cls.sp = make_config("https://sp.example.org", "sp")
        for key in ("display_name", "description", "info_url", "privacy_url", "org_name",
                    "org_display_name", "org_url", "technical_email", "support_email", "security_email", "disco_return_url"):
            setattr(cls.sp, key, "")
        cls.sp.idp_entity_id = cls.idp.entity_id
        cls.sp.discovery_url = ""
        cls.wrong_key = make_config("https://different-idp.example.org")

    def setUp(self):
        self.idp_xml = idp_logic.idp_metadata_xml(self.idp)
        self.sp_xml = sp_logic.sp_metadata_xml(self.sp)
        for target, cfg in [("idp.views.get_idp_config", self.idp), ("idp.slo.get_idp_config", self.idp),
                            ("sp.views.get_sp_config", self.sp), ("sp.slo.get_sp_config", self.sp)]:
            p = patch(target, return_value=cfg)
            p.start()
            self.addCleanup(p.stop)
        p = patch("idp.sp_resolver.resolve", side_effect=lambda entity: self.sp_xml if entity == self.sp.entity_id else None)
        p.start()
        self.addCleanup(p.stop)
        p = patch("sp.idp_resolver.resolve", side_effect=lambda entity: metadata.parse_entity(self.idp_xml) if entity == self.idp.entity_id else None)
        p.start()
        self.addCleanup(p.stop)
        self.user, self.password = create_user(username="alice", email="alice@example.org")
        self.idp_browser, self.sp_browser = Client(), Client()
        self.idp_browser.login(username="alice", password=self.password)
        self.login()

    def forward(self, response, client):
        if response.status_code == 302:
            url = urlsplit(response["Location"])
            return client.get(url.path + ("?" + url.query if url.query else ""))
        form = FormParser(response.content.decode())
        self.assertIsNotNone(form.action, response.content.decode())
        return client.post(urlsplit(form.action).path, form.inputs)

    def login(self, browser=None, expected_participants=1, expected_logins=1):
        browser = browser or self.sp_browser
        authn = browser.get("/sp/login/")
        response = self.forward(authn, self.idp_browser)
        self.assertEqual(response.status_code, 200)
        result = self.forward(response, browser)
        self.assertEqual(result.status_code, 302)
        self.assertIn("saml_identity", browser.session)
        self.assertEqual(SamlParticipant.objects.count(), expected_participants)
        self.assertEqual(SamlLogin.objects.filter(ended=False).count(), expected_logins)
        login = SamlLogin.objects.get(ended=False, session_key=browser.session.session_key)
        self.assertEqual(SamlParticipant.objects.get(session_index=login.session_index).name_id, login.name_id)

    def assert_signed_out(self):
        self.assertFalse(self.idp_browser.get("/idp/login/").wsgi_request.user.is_authenticated)
        self.assertNotIn("saml_identity", self.sp_browser.session)
        self.assertFalse(SamlParticipant.objects.exists())
        self.assertFalse(SamlLogin.objects.filter(ended=False).exists())

    def test_sp_initiated_redirect_roundtrip(self):
        request = self.sp_browser.post("/sp/logout/")
        self.assertTrue(LogoutTransaction.objects.exists())
        response = self.forward(request, Client())
        completed = self.forward(response, Client())
        self.assertContains(completed, "logout exchange completed")
        self.assertFalse(LogoutTransaction.objects.exists())
        self.assertEqual(self.forward(response, Client()).status_code, 400)
        self.assert_signed_out()

    def test_idp_initiated_redirect_roundtrip(self):
        request = self.idp_browser.post("/idp/logout/")
        self.assertTrue(LogoutFlow.objects.exists())
        response = self.forward(request, Client())
        completed = self.forward(response, Client())
        self.assertContains(completed, "All participating Service Providers confirmed logout")
        self.assertEqual(self.forward(request, Client()).status_code, 400)
        self.assert_signed_out()

    def only_post_endpoints(self):
        # SSO remains Redirect; only the SLO descriptor lines are modified.
        self.idp_xml = self.idp_xml.replace(f'<md:SingleLogoutService Binding="{core.BINDING_HTTP_REDIRECT}"',
                                          f'<md:SingleLogoutService Binding="{core.BINDING_SOAP}"')
        self.sp_xml = self.sp_xml.replace(f'<md:SingleLogoutService Binding="{core.BINDING_HTTP_REDIRECT}"',
                                        f'<md:SingleLogoutService Binding="{core.BINDING_SOAP}"')

    def test_sp_initiated_post_roundtrip_without_cookies(self):
        self.only_post_endpoints()
        request = self.sp_browser.post("/sp/logout/")
        self.assertEqual(request.status_code, 200)
        response = self.forward(request, Client())
        self.assertEqual(response.status_code, 200)
        completed = self.forward(response, Client())
        self.assertContains(completed, "logout exchange completed")
        self.assert_signed_out()

    def test_idp_initiated_post_roundtrip_without_cookies(self):
        self.only_post_endpoints()
        request = self.idp_browser.post("/idp/logout/")
        self.assertEqual(request.status_code, 200)
        response = self.forward(request, Client())
        completed = self.forward(response, Client())
        self.assertContains(completed, "All participating Service Providers confirmed logout")
        self.assert_signed_out()

    def request_to_sp(self, subject=None, indexes=None):
        login = SamlLogin.objects.get(ended=False)
        return saml_logout.create_sp_logout_request(saml_logout.SpLogoutRequestOptions(
            self.idp.entity_id, core.NameId(**(subject or login.name_id)), destination=self.sp.slo_url,
            session_indexes=indexes if indexes is not None else [login.session_index],
        ))

    def test_sp_rejects_unsigned_forged_subject_and_session_mismatches(self):
        request = self.request_to_sp()
        for binding in (core.BINDING_HTTP_REDIRECT, core.BINDING_HTTP_POST):
            self.assertEqual(deliver(Client(), request, self.idp, binding, path="/sp/slo/", signed=False).status_code, 400)
            self.assertEqual(deliver(Client(), request, self.wrong_key, binding, path="/sp/slo/").status_code, 400)
        subject = dict(SamlLogin.objects.get(ended=False).name_id, sp_name_qualifier="other-sp")
        for request in (self.request_to_sp(subject=subject), self.request_to_sp(indexes=["_unknown"])):
            response = deliver(Client(), request, self.idp, path="/sp/slo/")
            self.assertFalse(decoded_response(response)[1].is_success())
        self.assertIn("saml_identity", self.sp_browser.session)
        self.assertTrue(SamlLogin.objects.exists())

    def test_sp_rejects_forged_and_uncorrelated_responses(self):
        decoded, request = decoded_response(self.sp_browser.post("/sp/logout/"))
        for request_id, relay, signer, signed in [
            ("_wrong", decoded.relay_state, self.idp, True),
            (request.id, "wrong-relay", self.idp, True),
            (request.id, decoded.relay_state, self.wrong_key, True),
            (request.id, decoded.relay_state, self.idp, False),
        ]:
            response = saml_logout.create_logout_response_success(self.idp.entity_id, request_id, self.sp.slo_url)
            self.assertEqual(deliver(Client(), response, signer, relay=relay, signed=signed, path="/sp/slo/").status_code, 400)
            self.assertTrue(LogoutTransaction.objects.exists())
        response = saml_logout.create_logout_response_partial(self.idp.entity_id, request.id, self.sp.slo_url)
        final = deliver(Client(), response, self.idp, relay=decoded.relay_state, path="/sp/slo/")
        self.assertContains(final, "Other sessions may still be active")
        self.assertFalse(LogoutTransaction.objects.exists())

    def test_sp_local_logout_is_post_only_with_csrf(self):
        self.assertEqual(self.sp_browser.get("/sp/logout/").status_code, 405)
        client = Client(enforce_csrf_checks=True)
        client.cookies = self.sp_browser.cookies.copy()
        self.assertEqual(client.post("/sp/logout/").status_code, 403)
        self.assertIn("saml_identity", self.sp_browser.session)

    def test_sp_verifies_idp_rollover_key_and_reports_missing_tracking(self):
        import re
        key = re.search(r'<md:KeyDescriptor use="signing">.*?</md:KeyDescriptor>', self.idp_xml).group()
        self.idp_xml = self.idp_xml.replace(key, key.replace(self.idp.cert_b64, self.wrong_key.cert_b64) + key)
        for binding in (core.BINDING_HTTP_REDIRECT, core.BINDING_HTTP_POST):
            request = self.request_to_sp()
            response = deliver(Client(), request, self.idp, binding, path="/sp/slo/")
            self.assertTrue(decoded_response(response)[1].is_success())
            self.assertNotIn("saml_identity", self.sp_browser.session)
            # Establish a new tracked SSO session for the next binding.
            SamlParticipant.objects.all().delete()
            self.login()
        SamlLogin.objects.all().delete()
        final = self.sp_browser.post("/sp/logout/")
        self.assertContains(final, "Other sessions may still be active")

    def repeated_sso_logout(self, reverse_queue=False):
        from idp import slo as idp_slo

        def transient(cfg, destination, relay_state):
            request = profiles.create_authn_request(profiles.AuthnRequestOptions(
                cfg.entity_id, acs_url=cfg.acs_url, destination=destination,
                protocol_binding=core.BINDING_HTTP_POST, name_id_format=core.NAMEID_TRANSIENT,
            ))
            return bindings.redirect_encode(request.to_xml().encode(), True, destination, relay_state=relay_state), request.id

        with patch("sp.saml_logic.build_authn_redirect", side_effect=transient):
            self.login(expected_participants=2)
            first_subject = SamlLogin.objects.get(ended=False).name_id
            self.login(expected_participants=3)
        self.assertNotEqual(first_subject, SamlLogin.objects.get(ended=False).name_id)
        self.assertEqual(SamlLogin.objects.filter(ended=True).count(), 2)
        prepare = idp_slo.prepare_flow

        def ordered(*args, **kwargs):
            flow = prepare(*args, **kwargs)
            if reverse_queue:
                flow.queue.reverse()
            return flow

        with patch("idp.slo.prepare_flow", side_effect=ordered):
            response = self.idp_browser.post("/idp/logout/")
        for _ in range(3):
            reply = self.forward(response, Client())
            self.assertTrue(decoded_response(reply)[1].is_success())
            response = self.forward(reply, Client())
        self.assertContains(response, "All participating Service Providers confirmed logout")
        self.assert_signed_out()
        self.assertTrue(SamlLogin.objects.filter(ended=True).exists())

    def test_repeated_transient_sso_logout_recognizes_superseded_subjects(self):
        self.repeated_sso_logout()

    def test_current_session_can_logout_before_superseded_sessions_over_post(self):
        self.only_post_endpoints()
        self.repeated_sso_logout(reverse_queue=True)

    def test_origin_index_propagates_to_another_browser_at_same_sp(self):
        second = Client()
        self.login(browser=second, expected_participants=2, expected_logins=2)
        request = self.sp_browser.post("/sp/logout/")
        propagated = self.forward(request, Client())
        self.assertTrue(decoded_response(propagated)[0].is_request)
        reply = self.forward(propagated, Client())
        final_to_origin = self.forward(reply, Client())
        final = self.forward(final_to_origin, Client())
        self.assertContains(final, "logout exchange completed")
        self.assertNotIn("saml_identity", second.session)
        self.assert_signed_out()

    def test_old_subject_logout_cannot_end_a_new_principals_sp_session(self):
        old = self.request_to_sp()
        old_subject = SamlLogin.objects.get(ended=False).name_id
        _, password = create_user(username="bob", email="bob@example.org")
        # Same SP browser signs in as a different IdP principal.
        self.idp_browser.login(username="bob", password=password)
        self.login()
        current = SamlLogin.objects.get(ended=False)
        self.assertNotEqual(current.name_id, old_subject)
        reply = deliver(Client(), old, self.idp, path="/sp/slo/")
        self.assertTrue(decoded_response(reply)[1].is_success())
        self.assertIn("saml_identity", self.sp_browser.session)
        self.assertTrue(SamlLogin.objects.filter(pk=current.pk, ended=False).exists())

    def test_password_change_preserves_logout_associations_and_both_apps_logout(self):
        old_key = self.idp_browser.session.session_key
        response = self.idp_browser.post("/idp/profile/", {
            "old_password": self.password, "new_password1": "a new SAML teaching password",
            "new_password2": "a new SAML teaching password",
        })
        self.assertEqual(response.status_code, 302)
        self.assertNotEqual(self.idp_browser.session.session_key, old_key)
        self.assertEqual(SamlParticipant.objects.get().session_key, self.idp_browser.session.session_key)
        request = self.idp_browser.post("/idp/logout/")
        reply = self.forward(request, Client())
        completed = self.forward(reply, Client())
        self.assertContains(completed, "All participating Service Providers confirmed logout")
        self.assert_signed_out()

    def test_ended_association_outlives_stale_snapshot_while_browser_session_is_live(self):
        from datetime import timedelta
        from django.utils import timezone
        from sp import slo as sp_slo
        old_request = self.request_to_sp()
        self.login(expected_participants=2)
        SamlLogin.objects.filter(ended=True).update(expires_at=timezone.now() - timedelta(seconds=1))
        sp_slo.cleanup()
        self.assertTrue(SamlLogin.objects.filter(ended=True).exists())
        reply = deliver(Client(), old_request, self.idp, path="/sp/slo/")
        self.assertTrue(decoded_response(reply)[1].is_success())
        self.assertIn("saml_identity", self.sp_browser.session)

    def test_mixed_known_and_unknown_indexes_cannot_claim_logout_success(self):
        current = SamlLogin.objects.get(ended=False)
        request = self.request_to_sp(indexes=[current.session_index, "_unknown"])
        reply = deliver(Client(), request, self.idp, path="/sp/slo/")
        self.assertFalse(decoded_response(reply)[1].is_success())
        self.assertIn("saml_identity", self.sp_browser.session)

    def test_ended_records_are_removed_after_the_grace_period(self):
        from datetime import timedelta
        from django.utils import timezone
        from sp import slo as sp_slo
        self.sp_browser.post("/sp/logout/")
        self.assertTrue(SamlLogin.objects.filter(ended=True).exists())
        SamlLogin.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        sp_slo.cleanup()
        self.assertFalse(SamlLogin.objects.exists())
