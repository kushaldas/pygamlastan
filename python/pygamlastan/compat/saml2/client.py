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
from pygamlastan import SamlCryptoError
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


def _nameid_key(name_id: Any) -> tuple[str, str | None, str | None, str | None, str | None] | None:
    """Full identity tuple of a NameID-like value, for subject correlation.

    Returns ``(text, format, name_qualifier, sp_name_qualifier, sp_provided_id)``,
    normalising the shim :class:`~.saml.NameID` (``.text``), a pygamlastan core
    ``NameId`` (``.value``), or a bare string. The qualifiers are part of the SAML
    subject identity, so they are compared too (not just the text). Returns
    ``None`` when there is no identifier text to compare.
    """
    if name_id is None:
        return None
    text: str | None = None
    for attr in ("text", "value"):
        value = getattr(name_id, attr, None)
        if isinstance(value, str):
            text = value.strip()
            break
    if text is None and isinstance(name_id, str):
        text = name_id.strip()
    if not text:
        return None

    def _q(attr: str) -> str | None:
        value = getattr(name_id, attr, None)
        return value if isinstance(value, str) else None

    return (
        text,
        _q("format"),
        _q("name_qualifier"),
        _q("sp_name_qualifier"),
        _q("sp_provided_id"),
    )


def _maybe_b64_to_xml(raw: str | bytes) -> str:
    """Decode a SAMLResponse POST parameter (base64) to XML text.

    Line-wrapped base64 is supported by stripping interior whitespace explicitly,
    but decoding then uses ``validate=True`` so that any remaining non-alphabet
    character is rejected rather than silently ignored (which would let malformed,
    attacker-controlled input smuggle extra bytes past the decoder). If the input
    is already XML, or cannot be decoded to valid UTF-8 XML, it is returned
    unchanged so the caller's XML parser produces the error rather than this
    helper masking a recoverable case.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    candidate = raw.strip()
    if candidate.startswith("<"):
        return candidate
    # Drop only whitespace (line wrapping); everything else must be valid base64.
    compact = "".join(candidate.split())
    # Restore any padding a wrapped value may have lost.
    if len(compact) % 4:
        compact += "=" * (4 - len(compact) % 4)
    try:
        decoded = base64.b64decode(compact, validate=True)
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
        # Request HTTP-POST as the response ACS by default (the SAML Web SSO
        # norm), but config.acs falls back to the first configured ACS endpoint
        # when no POST ACS is declared, so an SP with only a different binding
        # can still build a request.
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
            # Sign whenever a key is configured (the generated SP metadata
            # advertises AuthnRequestsSigned="true" when key_file is set, so an
            # IdP relying on metadata expects signed requests). Derive a default
            # sig_alg from the key - as global_logout does - but honour an
            # explicit sigalg override.
            signer = None
            effective_sigalg = sigalg
            if sigalg or self.config.key_file:
                signer = self._get_signer()
                if effective_sigalg is None:
                    effective_sigalg = signer.signature_method_uri()
            url = _bindings.redirect_encode(
                xml.encode("utf-8"),
                True,
                sso_url,
                relay_state=rs,
                signer=signer,
                sig_alg=effective_sigalg,
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
        # Decode per the binding the response arrived over (HTTP-POST is base64,
        # HTTP-Redirect is DEFLATE+base64) inside the try, so a malformed
        # transport payload surfaces as StatusError too, rather than leaking a
        # low-level UnicodeDecodeError/zlib.error/binascii.Error to the caller.
        try:
            xml = self._decode_message(response, binding)
            parsed = _xml.parse_response(xml)
        except Exception as e:  # malformed transport or XML / not a Response
            # eduID treats parse failures as a bad response.
            raise StatusError(f"could not parse SAML response: {e}") from e

        in_response_to = parsed.in_response_to
        if outstanding is not None and in_response_to not in outstanding:
            raise UnsolicitedResponse(
                f"InResponseTo {in_response_to!r} not in outstanding queries"
            )

        # Recipient/ACS check uses the ACS for the binding this response actually
        # arrived over (config.acs falls back to the first configured ACS when the
        # exact binding is absent), rather than assuming HTTP-POST.
        acs_url, _ = self.config.acs(binding)
        # The expected IdP must be trusted, never taken from the unverified
        # Response issuer: with several IdPs that would let a signed response from
        # an unintended (but known) IdP be accepted. Use an explicit caller hint
        # or the unambiguous configured IdP; otherwise refuse.
        expected_idp = kwargs.get("expected_idp") or self.config.only_idp()
        if expected_idp is None:
            raise ValueError(
                "Cannot determine the expected IdP for response processing: more "
                "than one IdP is configured/known. Pass expected_idp=<entity id> "
                "(deriving it from the unverified Response issuer would be unsafe)."
            )

        if self.config.want_response_signed:
            # Use the safe-by-construction entry point: process_response_verified
            # performs XML-DSig verification over the EXACT bytes internally and
            # feeds only the cryptographically verified IDs into validation, so
            # there is no verified_signed_ids to thread (and no chance to mis-wire
            # it). Strict posture (signed responses/assertions, time and recipient
            # checks) but without mandating *encrypted* assertions: eduID, like
            # most SAML SPs, signs but does not encrypt assertions.
            verifier = SamlVerifier.from_cert(self.config.idp_signing_cert(expected_idp))
            cfg = _security.SecurityConfig.strict()
            cfg.require_encrypted_assertions = False
            try:
                result = _profiles.process_response_verified(
                    xml,
                    verifier,
                    cfg,
                    sp_entity_id,
                    acs_url,
                    expected_idp,
                    expected_request_id=in_response_to,
                    unsafe_no_replay_cache=True,
                    unsafe_no_persistent_id_store=True,
                )
            except SamlCryptoError as e:
                # Missing or invalid signature is checked first, before any
                # status/validation logic; eduID's get_authn_response catches
                # AssertionError as "SAML response is not verified".
                raise AssertionError(f"SAML response is not verified: {e}") from e
            except Exception as e:
                # Signature verified, but validation failed. A non-Success Status
                # surfaces as StatusError for pysaml2 parity (only after the
                # signature has been verified); anything else stays AssertionError.
                if not parsed.is_success():
                    raise StatusError(
                        "SAML response status not Success: "
                        f"{parsed.status.status_code.value}"
                    ) from e
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
        # Fail closed on a missing/blank subject rather than emitting
        # LogoutRequests with an empty NameID, matching _nameid_key's posture.
        if _nameid_key(name_id) is None:
            raise ValueError("global_logout requires a NameID with a non-empty identifier")
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
        # Subject correlation: the LogoutRequest must target the same principal as
        # the active session - compared over the FULL NameID (text plus Format and
        # the qualifiers, which are part of the SAML subject identity), not just
        # the text. Without this an IdP (or a replayed/forged request) could log
        # the wrong user out, so fail closed on any mismatch or missing NameID.
        expected_subject = _nameid_key(name_id)
        request_subject = _nameid_key(parsed.name_id)
        if (
            expected_subject is None
            or request_subject is None
            or request_subject != expected_subject
        ):
            raise ValueError(
                "LogoutRequest NameID does not match the session NameID"
            )
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
