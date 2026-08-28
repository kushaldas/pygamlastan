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
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
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


# gamlastan enforces assertion-replay protection unconditionally (validation
# check 20 fails closed without a cache), so the SP holds a replay cache with
# process lifetime. It must be shared by every Saml2Client instance: a
# per-instance cache would reset whenever the client is rebuilt (e.g. one
# client per request), letting an already-accepted assertion replay against
# the fresh instance. A single-process in-memory cache is sufficient for this
# shim; a multi-process deployment should inject a shared implementation via
# ``Saml2Client(config, replay_cache=...)``.
_PROCESS_REPLAY_CACHE = _security.InMemoryReplayCache()

# Evict expired replay entries periodically. gamlastan's check_and_insert only
# ever replaces the SAME expired ID and validation never calls cleanup(), so
# without this every accepted assertion/LogoutRequest ID would stay in the
# process-lifetime cache forever and a long-running SP would grow without
# bound. Cleanup is throttled process-wide: at most once per interval, run by
# whichever processing path comes along next.
# Maximum accepted age (from IssueInstant) for a LogoutRequest that declares
# no NotOnOrAfter. validate_logout_request only bounds requests that DECLARE
# NotOnOrAfter, so without this limit a captured request would stay valid
# forever while any finite replay-cache entry eventually expires - breaking
# one-time use. Replay entries are retained past this window, so a request can
# never outlive its replay entry.
_LOGOUT_REQUEST_MAX_AGE = timedelta(hours=24)

_REPLAY_CLEANUP_INTERVAL_SECONDS = 300.0
_replay_cleanup_lock = threading.Lock()
_last_replay_cleanup = 0.0


def _maybe_cleanup_replay_cache(cache: Any) -> None:
    global _last_replay_cleanup
    now = time.monotonic()
    with _replay_cleanup_lock:
        if now - _last_replay_cleanup < _REPLAY_CLEANUP_INTERVAL_SECONDS:
            return
        _last_replay_cleanup = now
    try:
        cache.cleanup()
    except Exception:
        # Eviction is maintenance, not a security decision (retaining an entry
        # longer is safe), so a failing injected cache must not abort the
        # authentication/logout flow - but it must not fail silently either.
        import warnings

        warnings.warn(
            "replay cache cleanup() failed; expired entries were not evicted",
            stacklevel=2,
        )


class Saml2Client:
    """pysaml2-compatible SP client backed by pygamlastan."""

    def __init__(
        self,
        config: SPConfig,
        identity_cache: Any = None,
        state_cache: Any = None,
        virtual_organization: Any = None,
        config_loader: Any = None,
        *,
        replay_cache: Any = None,
    ) -> None:
        self.config = config
        # Caches are accepted for API parity; the pygamlastan SP flow derives
        # logout targets from config/metadata rather than pysaml2's identity
        # bookkeeping, so they are not consulted here.
        self.identity_cache = identity_cache
        self.state_cache = state_cache
        self._signer: SamlSigner | None = None
        # Default to the shared process-lifetime cache; ``replay_cache`` lets a
        # multi-process deployment supply a shared implementation (any object
        # with ``check_and_insert(id, expiry) -> bool`` and ``cleanup()``).
        self._replay_cache = replay_cache if replay_cache is not None else _PROCESS_REPLAY_CACHE

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
            # The bindings post_encode API cannot sign, but the generated SP
            # metadata advertises AuthnRequestsSigned="true" when a key is
            # configured. Rather than silently emit an unsigned POST request that
            # an IdP may reject on the metadata's word, fail fast and steer the
            # caller to HTTP-Redirect (where request signing is implemented).
            if sigalg or self.config.key_file:
                raise ValueError(
                    "signed AuthnRequests are only supported over HTTP-Redirect; "
                    "use binding=BINDING_HTTP_REDIRECT (HTTP-POST request signing "
                    "is not implemented)"
                )
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

        # Both branches below insert into the replay cache; give expired
        # entries a periodic (throttled) chance to be evicted first.
        _maybe_cleanup_replay_cache(self._replay_cache)

        if self.config.want_response_signed:
            # Use the safe-by-construction entry point: process_response_verified
            # performs XML-DSig verification over the EXACT bytes internally and
            # feeds only the cryptographically verified IDs into validation, so
            # there is no verified_signed_ids to thread (and no chance to mis-wire
            # it). `want_response_signed` maps to a required Response-envelope
            # signature; it does not imply direct Assertion signatures.
            cfg = _security.SecurityConfig()
            cfg.require_signed_assertions = False
            cfg.require_signed_responses = True
            cfg.require_encrypted_assertions = False
            # During key rollover the IdP metadata publishes the old and new
            # signing certificates simultaneously, so try each until one
            # verifies cryptographically. A post-verification validation
            # failure is raised immediately: the signature already checked out
            # under that trusted certificate, and another certificate cannot
            # change the validation outcome.
            result = None
            crypto_error: SamlCryptoError | None = None
            for cert in self.config.idp_signing_certs(expected_idp):
                verifier = SamlVerifier.from_cert(cert)
                try:
                    result = _profiles.process_response_verified(
                        xml,
                        verifier,
                        cfg,
                        sp_entity_id,
                        acs_url,
                        expected_idp,
                        expected_request_id=in_response_to,
                        replay_cache=self._replay_cache,
                        unsafe_no_persistent_id_store=True,
                    )
                    break
                except SamlCryptoError as e:
                    # Missing signature, or not signed by this certificate:
                    # remember the failure and try the next published one.
                    crypto_error = e
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
            if result is None:
                # No published certificate verified the signature; eduID's
                # get_authn_response catches AssertionError as "SAML response
                # is not verified".
                raise AssertionError(
                    f"SAML response is not verified: {crypto_error}"
                ) from crypto_error
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
                    replay_cache=self._replay_cache,
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
        """Respond to an IdP-initiated LogoutRequest with a success response.

        SLO destroys the session keyed by the request-supplied NameID, so an
        unauthenticated request would let anyone who guesses a NameID force-log
        a victim out. The request is therefore cryptographically verified
        against the trusted IdP's metadata signing certificate before any
        session state is touched. For the HTTP-Redirect binding the signature is
        detached over the query string; pass ``sig_alg`` and ``signature``
        (the ``SigAlg``/``Signature`` query parameters) plus the exact
        ``signed_query`` string (the ``SAMLRequest``/``RelayState``/``SigAlg``
        portion the IdP signed) as keyword arguments. For POST the enveloped
        XML-DSig is verified directly.
        """
        sp_entity_id = self._require_entityid()
        # The expected IdP must be trusted, never taken from the unverified
        # request Issuer: with several IdPs that would let a signed request from
        # an unintended (but known) IdP authorize a logout. Use an explicit
        # caller hint or the unambiguous configured IdP; otherwise refuse.
        expected_idp = kwargs.get("expected_idp") or self.config.only_idp()
        if expected_idp is None:
            raise ValueError(
                "Cannot determine the expected IdP for LogoutRequest processing: "
                "more than one IdP is configured/known. Pass expected_idp=<entity id>."
            )
        # Decode, parse, verify, and validate inside one guard so transport/XML
        # failures (bad base64/DEFLATE/UTF-8, non-XML), signature failures, and
        # validation failures all surface uniformly as
        # ValueError("invalid LogoutRequest: ..."). validate_logout_request
        # requires the Issuer to equal the trusted IdP, proof of signature
        # verification, a present NameID, and an unexpired NotOnOrAfter (default
        # 180s skew), so an unsigned, misattributed, or stale LogoutRequest
        # cannot force-log out a session.
        try:
            xml = self._decode_message(request, binding)
            parsed = _xml.parse_logout_request(xml)
            signature_verified = self._verify_logout_request_signature(
                xml, binding, expected_idp, parsed, kwargs, relay_state
            )
            _logout.validate_logout_request(
                parsed,
                expected_idp,
                signature_verified,
                datetime.now(timezone.utc),
            )
        except Exception as e:
            raise ValueError(f"invalid LogoutRequest: {e}") from e
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
        # One-time use: signature verification alone does not stop a captured,
        # validly signed LogoutRequest from being submitted again - including
        # after the user logs in anew - to force-log out the fresh session.
        # Record the request ID atomically in the shared replay cache before
        # the success response authorizes any session destruction; a repeat
        # fails closed as a replay. The entry is retained through the request's
        # own NotOnOrAfter window (plus validation skew) when it declares one.
        # Without NotOnOrAfter, validation never expires the request, so this
        # handler enforces its own age limit from IssueInstant and retains the
        # replay entry past that whole window: the request is rejected as too
        # old before its replay entry can ever expire, keeping one-time use
        # airtight either way.
        now = datetime.now(timezone.utc)
        if parsed.not_on_or_after is not None:
            replay_expiry = parsed.not_on_or_after + timedelta(seconds=180)
        else:
            if now - parsed.issue_instant > _LOGOUT_REQUEST_MAX_AGE:
                raise ValueError(
                    "LogoutRequest without NotOnOrAfter is older than the "
                    f"maximum accepted age ({_LOGOUT_REQUEST_MAX_AGE})"
                )
            replay_expiry = (
                parsed.issue_instant + _LOGOUT_REQUEST_MAX_AGE + timedelta(seconds=180)
            )
        _maybe_cleanup_replay_cache(self._replay_cache)
        if not self._replay_cache.check_and_insert(parsed.id, replay_expiry):
            raise ValueError(
                "LogoutRequest replay detected: this request ID was already processed"
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

    def _verify_logout_request_signature(
        self,
        xml: str,
        binding: str,
        expected_idp: str,
        parsed: Any,
        kwargs: dict[str, Any],
        relay_state: str | None,
    ) -> bool:
        """Cryptographically verify an inbound LogoutRequest.

        Returns True only when a signature representation is present and every
        representation present verifies against one of the trusted IdP's
        metadata signing certificates (rollover metadata publishes the old and
        new certificates simultaneously, and any published certificate is
        trusted). Returns False when a trust anchor is configured but no
        signature is available, so the caller's ``validate_logout_request``
        fails closed. Raises on an invalid signature so a forged one cannot be
        silently downgraded to "unsigned".

        For the Redirect binding the detached signature only counts after the
        signed query has been bound to this exact message: its ``SAMLRequest``
        must decode to the XML being validated, its ``SigAlg`` must be the
        algorithm used for verification, and its ``RelayState`` must equal the
        one this handler will echo back (or be absent from both) - so a valid
        signed query from some other request cannot vouch for a substituted
        LogoutRequest, and an unsigned RelayState cannot ride along.

        When the IdP has no signing certificate configured (metadata-less dev
        setups, or deployments that authenticate the SLO channel at the
        transport layer) there is no trust anchor to verify against. This mirrors
        pysaml2's behavior and the ready IdP's ``allow_unauthenticated_backchannel``
        escape hatch: the request is accepted with a warning rather than
        verified. Configure IdP metadata with a signing certificate to enforce
        LogoutRequest signatures.
        """
        try:
            certs = self.config.idp_signing_certs(expected_idp)
        except ValueError:
            # The development fallback below is only for an IdP this SP
            # actually knows (configured or present in metadata) that merely
            # lacks a signing certificate. idp_signing_certs also raises for a
            # completely unknown entity ID, and letting that reach the
            # fallback would turn an arbitrary caller-supplied expected_idp
            # into a trusted unsigned issuer.
            if (
                expected_idp not in self.config.idp
                and expected_idp not in self.config.metadata
            ):
                raise ValueError(
                    f"unknown IdP {expected_idp!r}: not present in the SP "
                    "configuration or metadata"
                ) from None
            import warnings

            warnings.warn(
                "No signing certificate configured for IdP "
                f"{expected_idp!r}; accepting the LogoutRequest without "
                "signature verification. Configure IdP metadata with a signing "
                "certificate to enforce LogoutRequest signatures.",
                stacklevel=2,
            )
            return True
        verifiers = [SamlVerifier.from_cert(cert) for cert in certs]
        verified = False

        # HTTP-Redirect binding: detached signature over the query string. The
        # web handler must forward the SigAlg/Signature parameters and the exact
        # signed portion of the query it received. Any published (rollover)
        # certificate may have produced the signature.
        sig_alg = kwargs.get("sig_alg")
        signature = kwargs.get("signature")
        signed_query = kwargs.get("signed_query")
        # An incomplete tuple is an error, never "unsigned": a stripped
        # Signature parameter (the decoder permits SigAlg alone) must surface
        # as a hard failure rather than silently falling through to the
        # unsigned handling.
        if (
            binding == BINDING_HTTP_REDIRECT
            and any((sig_alg, signature, signed_query))
            and not (sig_alg and signature and signed_query)
        ):
            raise ValueError(
                "incomplete redirect signature: sig_alg, signature and "
                "signed_query must all be supplied together"
            )
        if binding == BINDING_HTTP_REDIRECT and sig_alg and signature and signed_query:
            # Bind the signed query to THIS message before trusting its
            # signature: a valid signed query captured from a different
            # (legitimate) LogoutRequest must not lend its signature to the
            # unsigned `request` being processed. The SAMLRequest inside the
            # signed query must decode to exactly the XML under validation,
            # and the SigAlg it carries must be the algorithm actually used
            # for verification.
            params: dict[str, str] = {}
            for part in signed_query.split("&"):
                key, _, value = part.partition("=")
                # unquote, not unquote_plus: the signed portion is the raw
                # percent-encoded query, where '+' is a literal plus
                # (base64), never an encoded space.
                params.setdefault(
                    urllib.parse.unquote(key), urllib.parse.unquote(value)
                )
            if params.get("SigAlg") != sig_alg:
                raise ValueError(
                    "SigAlg does not match the SigAlg inside the signed query"
                )
            # RelayState is covered by the detached signature too: the value
            # this handler will echo back must be exactly the signed one (or
            # absent from both), so an unsigned RelayState cannot be swapped
            # in alongside a validly signed query.
            if (relay_state or None) != (params.get("RelayState") or None):
                raise ValueError(
                    "RelayState does not match the RelayState inside the signed query"
                )
            query_request = params.get("SAMLRequest")
            if not query_request:
                raise ValueError("signed query carries no SAMLRequest")
            try:
                query_xml = self._decode_message(query_request, BINDING_HTTP_REDIRECT)
            except Exception as e:
                raise ValueError(
                    f"signed query SAMLRequest cannot be decoded: {e}"
                ) from e
            if query_xml != xml:
                raise ValueError(
                    "signed query SAMLRequest does not match the LogoutRequest "
                    "being processed"
                )
            raw_signature = base64.b64decode(signature)
            if not any(
                verifier.verify_redirect_query(
                    signed_query.encode("utf-8"), raw_signature, sig_alg
                )
                for verifier in verifiers
            ):
                raise ValueError("LogoutRequest redirect signature is invalid")
            verified = True

        # Enveloped XML-DSig (POST binding, or a redirect request that also
        # carries an enveloped signature). Bind the verified reference to the
        # request ID so a wrapped signature over a sibling object cannot count.
        if parsed.has_signature:
            last_error: Exception | None = None
            for verifier in verifiers:
                try:
                    signed_ids = [
                        ref
                        for result in verifier.verify_all_enveloped(xml)
                        for ref in result.signed_reference_ids()
                    ]
                except Exception as e:
                    # Not signed by this (rollover) certificate; try the next.
                    last_error = e
                    continue
                if parsed.id in signed_ids:
                    break
                last_error = ValueError(
                    "LogoutRequest XML signature does not cover the request element"
                )
            else:
                raise ValueError(
                    "LogoutRequest XML signature did not verify against any "
                    f"published IdP signing certificate: {last_error}"
                ) from last_error
            verified = True

        return verified

    @staticmethod
    def _decode_message(message: str, binding: str) -> str:
        """Decode a SAMLRequest/SAMLResponse parameter value to XML text."""
        if binding == BINDING_HTTP_REDIRECT:
            from .s_utils import decode_base64_and_inflate

            return decode_base64_and_inflate(message).decode("utf-8")
        return _maybe_b64_to_xml(message)
