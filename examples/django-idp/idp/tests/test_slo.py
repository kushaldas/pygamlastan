from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from threading import Barrier, Event
import re
from unittest.mock import patch

from django.contrib.sessions.models import Session
from django.db import close_old_connections, connections
from django.test import Client, TestCase, TransactionTestCase
from django.utils import timezone
from pygamlastan import bindings, core, crypto, logout as saml_logout, metadata, profiles, xml

from idp import saml_logic, slo
from idp.accounts import create_user
from idp.models import LogoutFlow, LogoutReplay, SamlParticipant
from .saml_helpers import decoded_response, deliver, make_config, sp_metadata


class LogoutTestMixin:
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.cfg = make_config("https://idp.example.org")
        cls.sp = make_config("https://sp.example.org", "sp")
        cls.other = make_config("https://other.example.org", "sp")

    def setUp(self):
        self.metadata = {self.sp.entity_id: sp_metadata(self.sp), self.other.entity_id: sp_metadata(self.other)}
        for target in ("idp.slo.get_idp_config", "idp.views.get_idp_config"):
            patcher = patch(target, return_value=self.cfg)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch("idp.sp_resolver.resolve", side_effect=self.metadata.get)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.user, self.password = create_user(username="alice", email="alice@example.org")
        self.browser = Client()
        self.browser.login(username="alice", password=self.password)
        self.subject = core.NameId("opaque-subject", format=core.NAMEID_PERSISTENT,
                                   name_qualifier=self.cfg.entity_id, sp_name_qualifier=self.sp.entity_id)
        self.participant = self.register(self.browser, self.sp, self.subject)

    def register(self, browser, sp, subject=None):
        return SamlParticipant.objects.create(
            session_key=browser.session.session_key, entity_id=sp.entity_id,
            name_id=slo.name_id_data(subject or self.subject), session_index=core.generate_id(),
            expires_at=timezone.now() + timedelta(hours=1),
        )

    def request(self, *, sp=None, subject=None, indexes=None, destination=None, expiry=None):
        return saml_logout.create_sp_logout_request(saml_logout.SpLogoutRequestOptions(
            (sp or self.sp).entity_id, subject or self.subject,
            session_indexes=indexes if indexes is not None else [self.participant.session_index],
            destination=destination or self.cfg.slo_url, not_on_or_after=expiry,
        ))

    def assert_browser_authenticated(self, expected=True):
        self.assertEqual(self.browser.get("/idp/login/").wsgi_request.user.is_authenticated, expected)


class SingleLogoutTests(LogoutTestMixin, TestCase):
    def test_metadata_advertises_both_slo_bindings(self):
        entity = metadata.parse_entity(saml_logic.idp_metadata_xml(self.cfg))
        self.assertEqual({(e.binding, e.location) for e in entity.single_logout_services("idp")},
                         {(core.BINDING_HTTP_REDIRECT, self.cfg.slo_url), (core.BINDING_HTTP_POST, self.cfg.slo_url)})

    def test_sp_initiated_redirect_and_post_are_signed_and_cookie_independent(self):
        for binding in (core.BINDING_HTTP_REDIRECT, core.BINDING_HTTP_POST):
            with self.subTest(binding=binding):
                if not SamlParticipant.objects.exists():
                    self.browser.login(username="alice", password=self.password)
                    self.participant = self.register(self.browser, self.sp)
                request = self.request()
                response = deliver(Client(), request, self.sp, binding, relay="kept-state")
                decoded, message = decoded_response(response)
                self.assertFalse(decoded.is_request)
                self.assertTrue(message.is_success())
                self.assertEqual(message.in_response_to, request.id)
                self.assertEqual(decoded.relay_state, "kept-state")
                verifier = crypto.SamlVerifier.from_cert(self.cfg.cert_pem)
                if binding == core.BINDING_HTTP_REDIRECT:
                    self.assertTrue(verifier.verify_redirect_query(decoded.signature_input.encode(), decoded.signature, decoded.sig_alg))
                else:
                    results = verifier.verify_all_enveloped(decoded.saml_xml.decode())
                    self.assertTrue(all(r.is_valid() for r in results))
                    self.assertIn(message.id, [i for r in results for i in r.signed_reference_ids()])
                self.assert_browser_authenticated(False)
                self.assertFalse(SamlParticipant.objects.exists())
                self.assertEqual(deliver(Client(), request, self.sp, binding).status_code, 400)

    def test_unsigned_wrong_key_destination_and_stale_requests_cannot_logout(self):
        request = self.request()
        cases = [
            (request, self.sp, {"signed": False}),
            (request, self.other, {}),
            (self.request(destination="https://elsewhere.example/slo"), self.sp, {}),
            (self.request(expiry=timezone.now() - timedelta(minutes=10)), self.sp, {}),
            (self.request(expiry=timezone.now() + timedelta(days=1)), self.sp, {}),
            (request, self.sp, {"text": re.sub(r'IssueInstant="[^"]+"', 'IssueInstant="2000-01-01T00:00:00Z"', request.to_xml())}),
        ]
        for request, signer, kwargs in cases:
            with self.subTest(kwargs=kwargs):
                self.assertEqual(deliver(Client(), request, signer, **kwargs).status_code, 400)
                self.assert_browser_authenticated()
        self.assertTrue(SamlParticipant.objects.exists())

    def test_nameid_format_qualifiers_and_session_indexes_are_bound(self):
        subjects = [
            core.NameId(self.subject.value, format=core.NAMEID_TRANSIENT, name_qualifier=self.cfg.entity_id, sp_name_qualifier=self.sp.entity_id),
            core.NameId(self.subject.value, format=core.NAMEID_PERSISTENT, name_qualifier="other-idp", sp_name_qualifier=self.sp.entity_id),
            core.NameId(self.subject.value, format=core.NAMEID_PERSISTENT, name_qualifier=self.cfg.entity_id, sp_name_qualifier="other-sp"),
        ]
        for subject in subjects:
            response = deliver(Client(), self.request(subject=subject), self.sp)
            self.assertFalse(decoded_response(response)[1].is_success())
            self.assert_browser_authenticated()
        response = deliver(Client(), self.request(indexes=["_wrong-index"]), self.sp)
        self.assertFalse(decoded_response(response)[1].is_success())
        self.assert_browser_authenticated()

    def test_mixed_known_and_unknown_indexes_reject_entire_request(self):
        for binding in (core.BINDING_HTTP_REDIRECT, core.BINDING_HTTP_POST):
            with self.subTest(binding=binding):
                response = deliver(Client(), self.request(indexes=[self.participant.session_index, "_unknown"]), self.sp, binding)
                self.assertFalse(decoded_response(response)[1].is_success())
                self.assertTrue(SamlParticipant.objects.filter(pk=self.participant.pk).exists())
                self.assertFalse(LogoutFlow.objects.exists())
                self.assert_browser_authenticated()

    def test_index_for_another_subject_does_not_count_as_a_match(self):
        other = self.register(self.browser, self.sp, core.NameId("different-subject"))
        response = deliver(Client(), self.request(indexes=[self.participant.session_index, other.session_index]), self.sp)
        self.assertFalse(decoded_response(response)[1].is_success())
        self.assertEqual(SamlParticipant.objects.count(), 2)
        self.assert_browser_authenticated()

    def test_repeated_changes_abort_local_logout_without_invalidating_sessions(self):
        prepare = slo.prepare_flow

        def keep_changing(*args, **kwargs):
            flow = prepare(*args, **kwargs)
            self.register(self.browser, self.other, core.NameId(core.generate_id()))
            return flow

        with patch("idp.slo.prepare_flow", side_effect=keep_changing):
            response = self.browser.post("/idp/logout/")
        self.assertEqual(response.status_code, 409)
        self.assertFalse(LogoutFlow.objects.exists())
        self.assert_browser_authenticated()

    def test_repeated_changes_return_signed_error_to_originating_sp(self):
        prepare = slo.prepare_flow

        def keep_changing(*args, **kwargs):
            flow = prepare(*args, **kwargs)
            self.register(self.browser, self.other, core.NameId(core.generate_id()))
            return flow

        with patch("idp.slo.prepare_flow", side_effect=keep_changing):
            response = deliver(Client(), self.request(), self.sp, relay="origin")
        decoded, message = decoded_response(response)
        self.assertFalse(message.is_success())
        self.assertEqual(decoded.relay_state, "origin")
        self.assertFalse(LogoutFlow.objects.exists())
        self.assert_browser_authenticated()

    def test_in_flight_sso_cannot_add_participant_after_logout_commits(self):
        from django.contrib.sessions.backends.base import UpdateError
        from django.contrib.sessions.backends.db import SessionStore
        from django.test import RequestFactory
        request = RequestFactory().get("/idp/sso/")
        request.session = SessionStore(session_key=self.browser.session.session_key)
        dict(request.session)  # The SSO request loaded its session before logout.
        signed = saml_logic.build_signed_response(
            sp_entity_id=self.other.entity_id, acs_url=self.other.acs_url,
            request_id="_another-authn-request", name_id_format=core.NAMEID_TRANSIENT,
            user=self.user, cfg=self.cfg,
        )
        self.assertEqual(self.browser.post("/idp/logout/").status_code, 302)
        with self.assertRaises(UpdateError):
            slo.record_issued(request, signed, self.other.entity_id)
        self.assertFalse(SamlParticipant.objects.exists())
        self.assertEqual({target["entity_id"] for target in LogoutFlow.objects.get().queue}, {self.sp.entity_id})

    def test_session_index_scopes_logout_to_one_browser(self):
        other_browser = Client()
        other_browser.login(username="alice", password=self.password)
        self.register(other_browser, self.sp)
        response = deliver(Client(), self.request(), self.sp)
        self.assertTrue(decoded_response(response)[1].is_success())
        self.assert_browser_authenticated(False)
        self.assertTrue(other_browser.get("/idp/login/").wsgi_request.user.is_authenticated)

    def test_omitted_session_indexes_log_out_all_matching_subject_sessions(self):
        other_browser = Client()
        other_browser.login(username="alice", password=self.password)
        self.register(other_browser, self.sp)
        response = deliver(Client(), self.request(indexes=[]), self.sp)
        self.assertTrue(decoded_response(response)[1].is_success())
        self.assertFalse(Session.objects.filter(session_key=other_browser.session.session_key).exists())
        self.assert_browser_authenticated(False)

    def test_sp_initiated_propagation_preserves_origin_and_reports_partial(self):
        other_subject = core.NameId("different-per-sp", format=core.NAMEID_TRANSIENT)
        other = self.register(self.browser, self.other, other_subject)
        origin = self.request()
        first = deliver(Client(), origin, self.sp, relay="origin-relay")
        decoded, propagated = decoded_response(first)
        self.assertTrue(decoded.is_request)
        self.assertEqual(propagated.issuer.value, self.cfg.entity_id)
        self.assertEqual(propagated.name_id.value, other_subject.value)
        self.assertEqual(propagated.session_indexes, [other.session_index])
        self.assert_browser_authenticated(False)
        response = saml_logout.create_logout_response_partial(self.other.entity_id, propagated.id, self.cfg.slo_url)
        final = deliver(Client(), response, self.other, relay=decoded.relay_state)
        returned, message = decoded_response(final)
        self.assertEqual(returned.relay_state, "origin-relay")
        self.assertEqual(message.in_response_to, origin.id)
        self.assertIn("PartialLogout", message.status.status_code.sub_status.value)
        self.assertFalse(LogoutFlow.objects.exists())

    def test_idp_initiated_logout_waits_for_verified_correlated_response(self):
        first = self.browser.post("/idp/logout/")
        decoded, propagated = decoded_response(first)
        self.assert_browser_authenticated(False)
        for issuer, request_id, relay in [
            (self.sp, "_wrong", decoded.relay_state),
            (self.other, propagated.id, decoded.relay_state),
            (self.sp, propagated.id, "wrong-relay"),
        ]:
            response = saml_logout.create_logout_response_success(issuer.entity_id, request_id, self.cfg.slo_url)
            self.assertEqual(deliver(Client(), response, issuer, relay=relay).status_code, 400)
            self.assertEqual(LogoutFlow.objects.get().queue[0]["id"], propagated.id)
        response = saml_logout.create_logout_response_success(self.sp.entity_id, propagated.id, self.cfg.slo_url)
        self.assertEqual(deliver(Client(), response, self.sp, signed=False, relay=decoded.relay_state).status_code, 400)
        final = deliver(Client(), response, self.sp, relay=decoded.relay_state)
        self.assertContains(final, "All participating Service Providers confirmed logout")
        self.assertEqual(deliver(Client(), response, self.sp, relay=decoded.relay_state).status_code, 400)

    def test_expired_flow_cannot_be_resumed(self):
        decoded, propagated = decoded_response(self.browser.post("/idp/logout/"))
        LogoutFlow.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        response = saml_logout.create_logout_response_success(self.sp.entity_id, propagated.id, self.cfg.slo_url)
        self.assertEqual(deliver(Client(), response, self.sp, relay=decoded.relay_state).status_code, 400)

    def test_missing_slo_endpoint_is_reported_as_partial(self):
        self.metadata[self.sp.entity_id] = sp_metadata(self.sp, binding=core.BINDING_SOAP)
        response = self.browser.post("/idp/logout/")
        self.assertContains(response, "Some Service Providers could not confirm logout")
        self.assert_browser_authenticated(False)

    def test_response_location_is_taken_only_from_registered_metadata(self):
        self.metadata[self.sp.entity_id] = sp_metadata(self.sp, response_location="https://sp.example.org/slo-response")
        response = deliver(Client(), self.request(), self.sp, relay="https://attacker.example/")
        self.assertTrue(response["Location"].startswith("https://sp.example.org/slo-response?"))
        self.assertEqual(decoded_response(response)[0].relay_state, "https://attacker.example/")

    def test_logout_is_post_only_and_csrf_protected(self):
        self.assertEqual(self.browser.get("/idp/logout/").status_code, 405)
        csrf = Client(enforce_csrf_checks=True)
        csrf.cookies = self.browser.cookies.copy()
        self.assertEqual(csrf.post("/idp/logout/").status_code, 403)
        self.assert_browser_authenticated()

    def test_signing_key_rollover_and_post_only_sp(self):
        self.metadata[self.sp.entity_id] = sp_metadata(self.sp, binding=core.BINDING_HTTP_POST, extra_cert=self.other.cert_b64)
        decoded, propagated = decoded_response(self.browser.post("/idp/logout/"))
        self.assertTrue(decoded.is_request)
        response = saml_logout.create_logout_response_success(self.sp.entity_id, propagated.id, self.cfg.slo_url)
        final = deliver(Client(), response, self.sp, binding=core.BINDING_HTTP_POST, relay=decoded.relay_state)
        self.assertContains(final, "All participating Service Providers confirmed logout")

    def test_real_sso_records_exact_issued_nameid_and_session_index(self):
        SamlParticipant.objects.all().delete()
        request = profiles.create_authn_request(profiles.AuthnRequestOptions(
            self.sp.entity_id, acs_url=self.sp.acs_url, destination=self.cfg.sso_url,
            protocol_binding=core.BINDING_HTTP_POST, name_id_format=core.NAMEID_TRANSIENT,
        ))
        from urllib.parse import urlsplit
        url = bindings.redirect_encode(request.to_xml().encode(), True, self.cfg.sso_url)
        response = self.browser.get("/idp/sso/?" + urlsplit(url).query)
        from .saml_helpers import FormParser
        decoded = bindings.post_decode(list(FormParser(response.content.decode()).inputs.items()))
        assertion = xml.parse_response(decoded.saml_xml.decode()).assertions[0]
        participant = SamlParticipant.objects.get()
        self.assertEqual(participant.name_id, slo.name_id_data(assertion.subject.name_id))
        self.assertEqual(participant.session_index, assertion.authn_statements[0].session_index)
        self.assertEqual(participant.session_key, self.browser.session.session_key)

    def test_post_body_and_redirect_signature_tampering_are_rejected(self):
        import base64
        from urllib.parse import parse_qsl, urlencode, urlsplit
        request = self.request()
        signed = slo.sign_message(request.to_xml(), request.id, self.sp)
        tampered = signed.replace(self.subject.value, "attacker-subject")
        response = Client().post("/idp/slo/", {"SAMLRequest": base64.b64encode(tampered.encode()).decode()})
        self.assertEqual(response.status_code, 400)
        url = bindings.redirect_encode(request.to_xml().encode(), True, self.cfg.slo_url,
                                       relay_state="original", signer=crypto.SamlSigner.from_pem(self.sp.key_pem),
                                       sig_alg="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        query = urlsplit(url).query
        self.assertEqual(Client().get("/idp/slo/?" + query.replace("original", "tampered")).status_code, 400)
        stripped = urlencode([(k, v) for k, v in parse_qsl(query) if k != "Signature"])
        self.assertEqual(Client().get("/idp/slo/?" + stripped).status_code, 400)
        self.assert_browser_authenticated()

    def test_unreachable_provider_can_be_skipped_with_partial_result(self):
        self.register(self.browser, self.other, core.NameId("other-subject", format=core.NAMEID_TRANSIENT))
        decoded, first = decoded_response(self.browser.post("/idp/logout/"))
        status = self.browser.get("/idp/logout/status/")
        self.assertContains(status, "Waiting for")
        self.assertEqual(self.browser.post("/idp/logout/status/", {"request_id": "_wrong"}).status_code, 400)
        next_response = self.browser.post("/idp/logout/status/", {"request_id": first.id})
        next_decoded, next_request = decoded_response(next_response)
        flow = LogoutFlow.objects.get()
        self.assertTrue(flow.partial)
        target = self.sp if next_request.destination == self.sp.slo_url else self.other
        response = saml_logout.create_logout_response_success(target.entity_id, next_request.id, self.cfg.slo_url)
        final = deliver(Client(), response, target, relay=next_decoded.relay_state)
        self.assertContains(final, "Some Service Providers could not confirm logout")
        self.assertEqual(deliver(Client(), saml_logout.create_logout_response_success(self.sp.entity_id, first.id, self.cfg.slo_url), self.sp,
                                 relay=decoded.relay_state).status_code, 400)

    def test_logout_status_is_csrf_protected_and_expiry_reports_partial(self):
        self.browser.post("/idp/logout/")
        flow = LogoutFlow.objects.get()
        client = Client(enforce_csrf_checks=True)
        client.cookies = self.browser.cookies.copy()
        self.assertEqual(client.post("/idp/logout/status/", {"request_id": flow.queue[0]["id"]}).status_code, 403)
        LogoutFlow.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertContains(self.browser.get("/idp/logout/status/"), "Some Service Providers could not confirm logout")

    def test_expired_participants_do_not_authorize_logout(self):
        SamlParticipant.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        Session.objects.filter(pk=self.browser.session.session_key).update(expire_date=timezone.now() - timedelta(seconds=1))
        response = deliver(Client(), self.request(), self.sp)
        self.assertFalse(decoded_response(response)[1].is_success())
        self.assert_browser_authenticated(False)

    def test_staggered_two_sp_login_keeps_earlier_participant_after_renewal(self):
        start = timezone.now()
        original_expiry = self.participant.expires_at
        request = profiles.create_authn_request(profiles.AuthnRequestOptions(
            self.other.entity_id, acs_url=self.other.acs_url, destination=self.cfg.sso_url,
            protocol_binding=core.BINDING_HTTP_POST, name_id_format=core.NAMEID_TRANSIENT,
        ))
        from urllib.parse import urlsplit
        url = bindings.redirect_encode(request.to_xml().encode(), True, self.cfg.sso_url)
        with patch("django.utils.timezone.now", return_value=start + timedelta(minutes=50)):
            self.assertEqual(self.browser.get("/idp/sso/?" + urlsplit(url).query).status_code, 200)
        self.participant.refresh_from_db()
        self.assertGreater(self.participant.expires_at, original_expiry + timedelta(minutes=40))
        with patch("django.utils.timezone.now", return_value=start + timedelta(minutes=65)):
            response = self.browser.post("/idp/logout/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual({item["entity_id"] for item in LogoutFlow.objects.get().queue},
                         {self.sp.entity_id, self.other.entity_id})

    def test_cleanup_uses_persisted_session_expiry_even_if_snapshot_is_stale(self):
        SamlParticipant.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        slo.cleanup()
        self.assertTrue(SamlParticipant.objects.filter(pk=self.participant.pk).exists())

    def test_origin_session_index_does_not_exclude_other_associations_at_same_sp(self):
        other_subject = core.NameId("another-session", format=core.NAMEID_TRANSIENT)
        other = self.register(self.browser, self.sp, other_subject)
        origin = self.request()
        decoded, propagated = decoded_response(deliver(Client(), origin, self.sp, relay="origin"))
        self.assertTrue(decoded.is_request)
        self.assertEqual(propagated.destination, self.sp.slo_url)
        self.assertEqual(propagated.name_id.value, other_subject.value)
        self.assertEqual(propagated.session_indexes, [other.session_index])
        response = saml_logout.create_logout_response_success(self.sp.entity_id, propagated.id, self.cfg.slo_url)
        final = deliver(Client(), response, self.sp, relay=decoded.relay_state)
        returned, result = decoded_response(final)
        self.assertEqual(returned.relay_state, "origin")
        self.assertEqual(result.in_response_to, origin.id)
        self.assertTrue(result.is_success())
        self.assertIsNone(result.status.status_code.sub_status)

    def test_cookie_less_cross_site_post_does_not_replace_unrelated_auth_cookie(self):
        from django.conf import settings
        self.register(self.browser, self.other, core.NameId("other-sp-session"))
        _, password = create_user(username="bob", email="bob@example.org")
        unrelated = Client()
        unrelated.login(username="bob", password=password)
        key = unrelated.session.session_key
        # Simulate SameSite=Lax: the browser sends no auth cookie on this POST,
        # then applies the returned Set-Cookie headers to its existing cookie jar.
        response = deliver(Client(), self.request(), self.sp, binding=core.BINDING_HTTP_POST)
        self.assertNotIn(settings.SESSION_COOKIE_NAME, response.cookies)
        self.assertIn(slo.RECOVERY_COOKIE, response.cookies)
        cookie = response.cookies[slo.RECOVERY_COOKIE]
        self.assertTrue(cookie["httponly"])
        self.assertTrue(cookie["secure"])
        self.assertEqual(cookie["path"], "/idp/logout/")
        unrelated.cookies.update(response.cookies)
        self.assertEqual(unrelated.session.session_key, key)
        self.assertEqual(unrelated.get("/idp/profile/").wsgi_request.user.username, "bob")
        self.assert_browser_authenticated(False)
        self.assertContains(unrelated.get("/idp/logout/status/"), "Waiting for")

    def test_recovery_cookie_signature_is_required(self):
        self.browser.post("/idp/logout/")
        self.browser.cookies[slo.RECOVERY_COOKIE] = "forged-recovery-token"
        self.assertContains(self.browser.get("/idp/logout/status/"), "Some Service Providers could not confirm logout")

    def test_recovery_post_for_completed_flow_returns_client_error(self):
        self.browser.post("/idp/logout/")
        flow = LogoutFlow.objects.get()
        identifier = flow.queue[0]["id"]
        flow.delete()
        response = self.browser.post("/idp/logout/status/", {"request_id": identifier})
        self.assertEqual(response.status_code, 400)

    def test_recovery_post_cannot_advance_expired_flow(self):
        self.browser.post("/idp/logout/")
        flow = LogoutFlow.objects.get()
        original = flow.queue.copy()
        LogoutFlow.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        response = self.browser.post("/idp/logout/status/", {"request_id": original[0]["id"]})
        self.assertEqual(response.status_code, 400)
        flow.refresh_from_db()
        self.assertEqual(flow.queue, original)

    def test_recovery_completion_deleted_after_locked_update_returns_client_error(self):
        self.browser.post("/idp/logout/")
        flow = LogoutFlow.objects.get()
        drive = slo.drive

        def completed_elsewhere(request, current, cfg):
            LogoutFlow.objects.filter(pk=current.pk).delete()
            return drive(request, current, cfg)

        with patch("idp.slo.drive", side_effect=completed_elsewhere):
            response = self.browser.post("/idp/logout/status/", {"request_id": flow.queue[0]["id"]})
        self.assertEqual(response.status_code, 400)


class LogoutPreparationRaceTests(LogoutTestMixin, TransactionTestCase):
    def race(self, initiator, mutation):
        if connections["default"].settings_dict["NAME"].startswith("file:memory"):
            self.skipTest("Use config.test_settings for SQLite writer-concurrency tests.")
        prepared, release = Event(), Event()
        prepare = slo.prepare_flow
        original_key = self.browser.session.session_key
        if mutation == "password" and initiator == "sp":
            self.register(self.browser, self.other, core.NameId("other-sp-subject"))
        logout_browser = Client()
        logout_browser.cookies = self.browser.cookies.copy()
        logout_request = self.request()

        def pause_preparation(*args, **kwargs):
            self.assertFalse(connections["default"].in_atomic_block, "Metadata work must not hold a write transaction.")
            flow = prepare(*args, **kwargs)
            if not prepared.is_set():
                prepared.set()
                if not release.wait(timeout=15):
                    raise AssertionError("Concurrent mutation did not complete.")
            return flow

        def start_logout():
            close_old_connections()
            try:
                if initiator == "local":
                    return logout_browser.post("/idp/logout/")
                return deliver(Client(), logout_request, self.sp)
            finally:
                connections.close_all()

        with patch("idp.slo.prepare_flow", side_effect=pause_preparation), ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(start_logout)
            try:
                self.assertTrue(prepared.wait(timeout=15))
                if mutation == "password":
                    response = self.browser.post("/idp/profile/", {
                        "old_password": self.password, "new_password1": "a newer teaching password",
                        "new_password2": "a newer teaching password",
                    })
                    self.assertEqual(response.status_code, 302)
                    current_key = self.browser.session.session_key
                    self.assertNotEqual(current_key, original_key)
                else:
                    from urllib.parse import urlsplit
                    authn = profiles.create_authn_request(profiles.AuthnRequestOptions(
                        self.other.entity_id, acs_url=self.other.acs_url, destination=self.cfg.sso_url,
                        protocol_binding=core.BINDING_HTTP_POST, name_id_format=core.NAMEID_TRANSIENT,
                    ))
                    url = bindings.redirect_encode(authn.to_xml().encode(), True, self.cfg.sso_url)
                    self.assertEqual(self.browser.get("/idp/sso/?" + urlsplit(url).query).status_code, 200)
                    current_key = self.browser.session.session_key
                    self.assertTrue(SamlParticipant.objects.filter(entity_id=self.other.entity_id).exists())
            finally:
                release.set()
            response = future.result(timeout=20)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(decoded_response(response)[0].is_request)
        expected = {self.sp.entity_id, self.other.entity_id} if initiator == "local" and mutation == "sso" else {self.other.entity_id}
        if initiator == "local" and mutation == "password":
            expected = {self.sp.entity_id}
        self.assertEqual({target["entity_id"] for target in LogoutFlow.objects.get().queue}, expected)
        self.assertFalse(Session.objects.filter(pk=current_key).exists())
        self.assertFalse(SamlParticipant.objects.exists())
        self.assert_browser_authenticated(False)

    def test_local_logout_follows_concurrent_password_rotation(self):
        self.race("local", "password")

    def test_sp_logout_follows_concurrent_password_rotation(self):
        self.race("sp", "password")

    def test_local_logout_includes_concurrent_sso_participant(self):
        self.race("local", "sso")

    def test_sp_logout_includes_concurrent_sso_participant(self):
        self.race("sp", "sso")

    def test_logout_during_password_hashing_cannot_restore_login(self):
        from django.contrib.auth.forms import PasswordChangeForm
        from django.conf import settings
        if connections["default"].settings_dict["NAME"].startswith("file:memory"):
            self.skipTest("Use config.test_settings for SQLite writer-concurrency tests.")
        hashed, release = Event(), Event()
        save = PasswordChangeForm.save
        browser = Client()
        browser.cookies = self.browser.cookies.copy()

        def pause_hashing(form, commit=True):
            user = save(form, commit=commit)
            self.assertFalse(connections["default"].in_atomic_block)
            hashed.set()
            if not release.wait(timeout=15):
                raise AssertionError("Concurrent logout did not finish.")
            return user

        def change_password():
            close_old_connections()
            try:
                return browser.post("/idp/profile/", {
                    "old_password": self.password, "new_password1": "a racing teaching password",
                    "new_password2": "a racing teaching password",
                })
            finally:
                connections.close_all()

        with patch.object(PasswordChangeForm, "save", pause_hashing), ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(change_password)
            try:
                self.assertTrue(hashed.wait(timeout=15))
                self.assertEqual(self.browser.post("/idp/logout/").status_code, 302)
            finally:
                release.set()
            response = future.result(timeout=20)
        self.assertEqual(response.status_code, 409)
        self.assertNotIn(settings.SESSION_COOKIE_NAME, response.cookies)
        self.assertFalse(Session.objects.exists())
        self.assertFalse(SamlParticipant.objects.exists())
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))

    def test_recovery_post_and_logout_response_serialize_completion(self):
        from django.db.models.query import QuerySet
        if connections["default"].settings_dict["NAME"].startswith("file:memory"):
            self.skipTest("Use config.test_settings for SQLite writer-concurrency tests.")
        self.browser.post("/idp/logout/")
        flow = LogoutFlow.objects.get()
        identifier = flow.queue[0]["id"]
        message = saml_logout.create_logout_response_success(self.sp.entity_id, identifier, self.cfg.slo_url)
        loaded, release, callback_started = Event(), Event(), Event()
        first = QuerySet.first
        browser = Client()
        browser.cookies = self.browser.cookies.copy()

        def pause_read(query):
            current = first(query)
            if query.model is LogoutFlow and current is not None and not loaded.is_set():
                loaded.set()
                if not release.wait(timeout=15):
                    raise AssertionError("Recovery read was not released.")
            return current

        def recover():
            close_old_connections()
            try:
                return browser.post("/idp/logout/status/", {"request_id": identifier})
            finally:
                connections.close_all()

        def respond():
            close_old_connections()
            try:
                callback_started.set()
                return deliver(Client(), message, self.sp, relay=flow.token)
            finally:
                connections.close_all()

        with patch.object(QuerySet, "first", pause_read), ThreadPoolExecutor(max_workers=2) as executor:
            recovery = executor.submit(recover)
            try:
                self.assertTrue(loaded.wait(timeout=15))
                callback = executor.submit(respond)
                self.assertTrue(callback_started.wait(timeout=15))
                with self.assertRaises(FutureTimeout):
                    callback.result(timeout=.25)
            finally:
                release.set()
            self.assertEqual(recovery.result(timeout=20).status_code, 200)
            self.assertEqual(callback.result(timeout=20).status_code, 400)
        self.assertFalse(LogoutFlow.objects.exists())


class LogoutReplayConcurrencyTests(TransactionTestCase):
    def test_database_replay_reservation_is_atomic_and_issuer_scoped(self):
        if connections["default"].settings_dict["NAME"].startswith("file:memory"):
            self.skipTest("Use config.test_settings for SQLite writer-concurrency tests.")
        barrier = Barrier(2)

        def reserve(_):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                return slo.ReplayCache("sp-one").check_and_insert("same-request", timezone.now() + timedelta(minutes=5))
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertCountEqual(list(executor.map(reserve, range(2))), [True, False])
        self.assertFalse(slo.ReplayCache("sp-one").check_and_insert("same-request", timezone.now()))
        self.assertTrue(slo.ReplayCache("sp-two").check_and_insert("same-request", timezone.now()))
        self.assertEqual(LogoutReplay.objects.count(), 2)
