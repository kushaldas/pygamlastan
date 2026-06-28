"""``saml2.client`` shim: :class:`Saml2Client`, backed by pygamlastan.

Reproduces the SP-side methods eduID calls:

* ``prepare_for_authenticate`` -> ``(session_id, http_info)``
* ``parse_authn_request_response`` -> :class:`~.response.AuthnResponse`
* ``global_logout`` -> ``{idp_entity_id: (request_id, http_info)}``
* ``parse_logout_request_response`` -> :class:`~.response.LogoutResponse`
* ``handle_logout_request`` -> ``http_info``

``http_info`` mirrors pysaml2's shape: a dict whose ``headers`` is a list with a
``("Location", url)`` entry for the HTTP-Redirect binding.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from pygamlastan import bindings as _bindings
from pygamlastan import profiles as _profiles
from pygamlastan import security as _security
from pygamlastan import xml as _xml
from pygamlastan import logout as _logout
from pygamlastan.core import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from pygamlastan.crypto import SamlSigner, SamlVerifier

from .config import SPConfig
from .response import AuthnResponse, LogoutResponse, StatusError, UnsolicitedResponse
from .saml import NameID


def _redirect_http_info(url: str) -> dict[str, Any]:
    """pysaml2-shaped http_info for the HTTP-Redirect binding."""
    return {
        "method": "GET",
        "url": url,
        "headers": [("Location", url)],
        "data": [],
    }


def _post_http_info(url: str, html: str) -> dict[str, Any]:
    """pysaml2-shaped http_info for the HTTP-POST binding (auto-submit form)."""
    return {
        "method": "POST",
        "url": url,
        "headers": [("Content-type", "text/html")],
        "data": html,
    }


def _maybe_b64_to_xml(raw: str | bytes) -> str:
    """Decode a SAMLResponse POST parameter (base64) to XML text.

    Base64 is decoded leniently (whitespace/newlines from line-wrapped values
    are tolerated). If the input is already XML, or cannot be decoded to valid
    UTF-8 XML, it is returned unchanged so the caller's XML parser produces the
    error rather than this helper masking a recoverable case.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    candidate = raw.strip()
    if candidate.startswith("<"):
        return candidate
    try:
        # validate=False (default) ignores non-alphabet chars, so wrapped/
        # whitespaced base64 still decodes.
        decoded = base64.b64decode(candidate)
        text = decoded.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return candidate
    # Only accept the decoded payload if it actually looks like XML.
    return text if text.lstrip().startswith("<") else candidate


class Saml2Client:
    """pysaml2-compatible SP client backed by pygamlastan."""

    def __init__(
        self,
        config: SPConfig,
        identity_cache: Any = None,
        state_cache: Any = None,
        virtual_organization: Any = None,
        config_loader: Any = None,
    ) -> None:
        self.config = config
        # Caches are accepted for API parity; the pygamlastan SP flow derives
        # logout targets from config/metadata rather than pysaml2's identity
        # bookkeeping, so they are not consulted here.
        self.identity_cache = identity_cache
        self.state_cache = state_cache
        self._signer: SamlSigner | None = None

    # -- signing helper ---------------------------------------------------

    def _get_signer(self) -> SamlSigner:
        if self._signer is None:
            if not self.config.key_file:
                raise ValueError("signing requested but no key_file configured")
            with open(self.config.key_file, "rb") as fh:
                self._signer = SamlSigner.from_pem(fh.read())
        return self._signer

    def _require_entityid(self) -> str:
        if not self.config.entityid:
            raise ValueError("SPConfig.entityid is required for SP requests/responses")
        return self.config.entityid

    # -- AuthnRequest -----------------------------------------------------

    def prepare_for_authenticate(
        self,
        entityid: str | None = None,
        relay_state: str = "",
        binding: str = BINDING_HTTP_REDIRECT,
        sigalg: str | None = None,
        digest_alg: str | None = None,
        subject: Any = None,
        force_authn: str | bool = "false",
        requested_authn_context: Any = None,
        **kwargs: Any,
    ) -> tuple[str, dict[str, Any]]:
        idp = entityid or self.config.only_idp()
        if idp is None:
            # pysaml2 raises TypeError here; eduID catches it to mean
            # "unable to know which IdP to use".
            raise TypeError("Unable to determine which IdP to use")

        # Prefer the SSO endpoint published for the requested binding; fall back
        # to Redirect (the only binding gamlastan currently encodes a request
        # for) if the IdP does not advertise the requested one.
        try:
            sso_url = self.config.single_sign_on_service(idp, binding)
        except ValueError:
            sso_url = self.config.single_sign_on_service(idp, BINDING_HTTP_REDIRECT)
        acs_url, acs_binding = self.config.acs(BINDING_HTTP_POST)

        force = str(force_authn).lower() in ("true", "1", "yes")

        class_refs: list[str] | None = None
        comparison: str | None = None
        if requested_authn_context:
            ref = requested_authn_context.get("authn_context_class_ref")
            if isinstance(ref, str):
                class_refs = [ref]
            elif ref is not None:
                class_refs = list(ref)
            comparison = requested_authn_context.get("comparison", "exact")

        options = _profiles.AuthnRequestOptions(
            sp_entity_id=self._require_entityid(),
            acs_url=acs_url,
            protocol_binding=acs_binding,
            force_authn=force,
            authn_context_class_refs=class_refs,
            authn_context_comparison=comparison,
            destination=sso_url,
        )
        request = _profiles.create_authn_request(options)
        session_id = request.id
        xml = request.to_xml()

        rs = relay_state or None
        if binding == BINDING_HTTP_REDIRECT:
            signer = self._get_signer() if sigalg else None
            url = _bindings.redirect_encode(
                xml.encode("utf-8"), True, sso_url, relay_state=rs, signer=signer, sig_alg=sigalg
            )
            return session_id, _redirect_http_info(url)
        elif binding == BINDING_HTTP_POST:
            html = _bindings.post_encode(xml.encode("utf-8"), True, sso_url, relay_state=rs)
            return session_id, _post_http_info(sso_url, html)
        raise ValueError(f"unsupported binding for AuthnRequest: {binding}")

    # -- Response processing ----------------------------------------------

    def parse_authn_request_response(
        self,
        response: str,
        binding: str,
        outstanding: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> AuthnResponse:
        sp_entity_id = self._require_entityid()
        # Decode per the binding the response arrived over: HTTP-POST is base64,
        # HTTP-Redirect is DEFLATE+base64.
        xml = self._decode_message(response, binding)
        try:
            parsed = _xml.parse_response(xml)
        except Exception as e:  # malformed XML / not a Response
            # eduID treats parse failures as a bad response.
            raise StatusError(f"could not parse SAML response: {e}") from e

        in_response_to = parsed.in_response_to
        if outstanding is not None and in_response_to not in outstanding:
            raise UnsolicitedResponse(
                f"InResponseTo {in_response_to!r} not in outstanding queries"
            )

        acs_url, _ = self.config.acs(BINDING_HTTP_POST)
        expected_idp = self.config.only_idp()
        if expected_idp is None and parsed.issuer is not None:
            expected_idp = parsed.issuer.value

        if self.config.want_response_signed:
            # Verify the signature FIRST. Checking the Status before verification
            # would let an unsigned non-Success Response drive control flow and
            # bypass the "signatures required" policy, so the status check moves
            # after verification here.
            verifier = SamlVerifier.from_cert(self.config.idp_signing_cert(expected_idp))
            try:
                verify = verifier.verify_enveloped(xml)
                valid = verify.is_valid()
            except Exception as e:
                # An unsigned response raises here (no Signature element); treat
                # it like any other verification failure.
                raise AssertionError(f"SAML response is not verified: {e}") from e
            if not valid:
                # eduID's get_authn_response catches AssertionError as
                # "SAML response is not verified".
                raise AssertionError(f"SAML response signature invalid: {verify.reason}")
            self._raise_on_failed_status(parsed)
            # Strict posture (signed responses/assertions required, time and
            # recipient checks on) but without mandating *encrypted* assertions:
            # eduID, like most SAML SPs, signs but does not encrypt assertions.
            cfg = _security.SecurityConfig.strict()
            cfg.require_encrypted_assertions = False
            try:
                result = _profiles.process_response(
                    parsed,
                    cfg,
                    sp_entity_id,
                    acs_url,
                    expected_idp,
                    expected_request_id=in_response_to,
                    verified_signed_ids=verify.signed_reference_ids(),
                    unsafe_no_replay_cache=True,
                    unsafe_no_persistent_id_store=True,
                )
            except Exception as e:
                raise AssertionError(f"SAML response validation failed: {e}") from e
        else:
            # Unsigned responses are only acceptable in dev/test, where the
            # settings explicitly set want_response_signed=False.
            self._raise_on_failed_status(parsed)
            cfg = _security.SecurityConfig.permissive()
            try:
                result = _profiles.process_response(
                    parsed,
                    cfg,
                    sp_entity_id,
                    acs_url,
                    expected_idp,
                    expected_request_id=in_response_to,
                    verified_signed_ids=[],
                    unsafe_no_replay_cache=True,
                    unsafe_no_persistent_id_store=True,
                )
            except Exception as e:
                raise AssertionError(f"SAML response processing failed: {e}") from e

        return AuthnResponse(result, in_response_to)

    @staticmethod
    def _raise_on_failed_status(parsed: Any) -> None:
        if not parsed.is_success():
            raise StatusError(
                f"SAML response status not Success: {parsed.status.status_code.value}"
            )

    # -- Single Logout ----------------------------------------------------

    def global_logout(
        self, name_id: NameID, reason: str = "", expire: Any = None, sign: Any = None
    ) -> dict[str, tuple[str, dict[str, Any]]]:
        """Build SP-initiated LogoutRequests for each federated IdP with an SLO.

        IdPs are discovered from both the ``idp`` config block and parsed
        metadata, so metadata-only deployments are covered too.
        """
        sp_entity_id = self._require_entityid()
        core_name_id = name_id.to_core()
        # When signing is requested, _get_signer raises if no key_file is
        # configured - fail fast rather than silently sending unsigned.
        signer = self._get_signer() if sign else None
        sig_alg = signer.signature_method_uri() if signer is not None else None

        candidate_idps = list(self.config.idp) + [
            eid for eid in self.config.metadata if eid not in self.config.idp
        ]
        out: dict[str, tuple[str, dict[str, Any]]] = {}
        for idp in candidate_idps:
            try:
                slo_url = self.config.single_logout_service(idp, BINDING_HTTP_REDIRECT)
            except ValueError:
                continue
            options = _logout.SpLogoutRequestOptions(
                sp_entity_id=sp_entity_id,
                name_id=core_name_id,
                reason=reason or None,
                destination=slo_url,
            )
            request = _logout.create_sp_logout_request(options)
            # redirect_encode requires a sig_alg whenever a signer is given;
            # derive it from the signer's own signature method.
            url = _bindings.redirect_encode(
                request.to_xml().encode("utf-8"),
                True,
                slo_url,
                signer=signer,
                sig_alg=sig_alg,
            )
            out[idp] = (request.id, _redirect_http_info(url))
        return out

    def parse_logout_request_response(
        self, response: str, binding: str = BINDING_HTTP_REDIRECT, **kwargs: Any
    ) -> LogoutResponse:
        xml = self._decode_message(response, binding)
        parsed = _xml.parse_logout_response(xml)
        return LogoutResponse(parsed.is_success(), in_response_to=parsed.in_response_to)

    def handle_logout_request(
        self,
        request: str,
        name_id: NameID,
        binding: str = BINDING_HTTP_REDIRECT,
        relay_state: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Respond to an IdP-initiated LogoutRequest with a success response."""
        sp_entity_id = self._require_entityid()
        xml = self._decode_message(request, binding)
        parsed = _xml.parse_logout_request(xml)
        issuer = parsed.issuer.value if parsed.issuer is not None else self.config.only_idp()
        slo_url = self.config.single_logout_service(issuer, BINDING_HTTP_REDIRECT)
        resp = _logout.create_logout_response_success(
            sp_entity_id, parsed.id, destination=slo_url
        )
        url = _bindings.redirect_encode(
            resp.to_xml().encode("utf-8"),
            False,
            slo_url,
            relay_state=relay_state or None,
        )
        return _redirect_http_info(url)

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _decode_message(message: str, binding: str) -> str:
        """Decode a SAMLRequest/SAMLResponse parameter value to XML text."""
        if binding == BINDING_HTTP_REDIRECT:
            from .s_utils import decode_base64_and_inflate

            return decode_base64_and_inflate(message).decode("utf-8")
        return _maybe_b64_to_xml(message)
