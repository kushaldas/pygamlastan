"""``saml2.client`` shim: :class:`Saml2Client`, backed by pygamlastan.

Reproduces the SP-side methods eduID calls:

* ``prepare_for_authenticate`` -> ``(session_id, http_info)``
* ``parse_authn_request_response`` -> :class:`~.response.AuthnResponse`
* ``global_logout`` -> ``{idp_entity_id: (binding, http_info)}``
* ``parse_logout_request_response`` -> :class:`~.response.LogoutResponse`
* ``handle_logout_request`` -> ``http_info``

``http_info`` mirrors pysaml2's shape: a dict whose ``headers`` is a list with a
``("Location", url)`` entry for the HTTP-Redirect binding.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any

from pygamlastan import SamlCryptoError, SamlXmlError
from pygamlastan import bindings as _bindings
from pygamlastan import logout as _logout
from pygamlastan import profiles as _profiles
from pygamlastan import security as _security
from pygamlastan import xml as _xml
from pygamlastan.core import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from pygamlastan.crypto import KeysManager, SamlDecryptor, SamlSigner, SamlVerifier

from .client_base import LogoutError
from .config import SPConfig
from .ident import code, decode
from .response import (
    AuthnResponse,
    LogoutResponse,
    RequestVersionTooLow,
    SignatureError,
    StatusAuthnFailed,
    StatusError,
    StatusNoAuthnContext,
    StatusRequestDenied,
    UnsolicitedResponse,
)
from .s_utils import UnsupportedBinding
from .saml import NAMEID_FORMAT_TRANSIENT, NameID
from .sigver import MissingKey
from .validate import ResponseLifetimeExceed, ToEarly
from .xmldsig import DIGEST_SHA256


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


def _matches_legacy_logout_relay_state(
    request_id: str, relay_state: str, secret: Any
) -> bool:
    """Validate RelayState emitted by pysaml2 or the earlier shim.

    Older pygamlastan releases used the request ID directly. pysaml2 used
    ``request-id|timestamp|HMAC-SHA1`` but did not persist that value alongside
    its request state, so rolling upgrades must validate the legacy encoding.
    """
    if relay_state == request_id:
        return True
    parts = relay_state.split("|")
    if len(parts) != 3 or parts[0] != request_id:
        return False
    try:
        int(parts[1])
    except ValueError:
        return False
    if secret is None:
        secret_bytes = b""
    elif isinstance(secret, bytes):
        secret_bytes = secret
    else:
        secret_bytes = str(secret).encode("utf-8")
    digest = hmac.new(secret_bytes, digestmod=hashlib.sha1)
    digest.update(parts[0].encode("utf-8"))
    digest.update(parts[1].encode("utf-8"))
    return hmac.compare_digest(digest.hexdigest(), parts[2])


def _signature_template(
    element_id: str, signature_algorithm: str, digest_algorithm: str
) -> str:
    """Build the enveloped XML-DSig template consumed by ``SamlSigner``.

    All three values originate from typed configuration or a generated SAML ID.
    XML attribute escaping is nevertheless applied so the helper remains safe if
    a custom ID generator or algorithm registry is introduced later.
    """
    from xml.sax.saxutils import quoteattr

    return (
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        "<ds:SignedInfo>"
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        f"<ds:SignatureMethod Algorithm={quoteattr(signature_algorithm)}/>"
        f"<ds:Reference URI={quoteattr('#' + element_id)}><ds:Transforms>"
        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        "</ds:Transforms>"
        f"<ds:DigestMethod Algorithm={quoteattr(digest_algorithm)}/>"
        "<ds:DigestValue/></ds:Reference></ds:SignedInfo>"
        "<ds:SignatureValue/></ds:Signature>"
    )


def _sign_enveloped_request(
    xml: str,
    element_id: str,
    signer: SamlSigner,
    signature_algorithm: str | None,
    digest_algorithm: str | None,
) -> str:
    """Insert a signature template after Issuer and sign the request root."""
    issuer_end = re.search(r"</(?:[A-Za-z_][\w.-]*:)?Issuer\s*>", xml)
    if issuer_end is None:
        raise ValueError("cannot sign a SAML request without an Issuer element")
    template = _signature_template(
        element_id,
        signature_algorithm or signer.signature_method_uri(),
        digest_algorithm or DIGEST_SHA256,
    )
    templated = xml[: issuer_end.end()] + template + xml[issuer_end.end() :]
    return signer.sign_enveloped(templated)


def _legacy_nil_attributes(xml: str, assertion_id: str) -> list[Any]:
    """Recover contradictory nil values from the authenticated assertion.

    Older pysaml2 accepted an ``AttributeValue`` that simultaneously declared
    itself nil and contained text.  A schema-aware parser correctly represents
    that value as null, but djangosaml2's long-standing test fixtures—and some
    legacy IdPs—expect the text to win.  This adapter runs only after the native
    hardened parser has accepted the document and never changes the bytes used
    for signature verification. Recovered values retain only their wire name
    and NameFormat; FriendlyName is deliberately ignored so the strict native
    attribute converter remains the authority for local names.
    """
    from xml.etree import ElementTree

    from pygamlastan.core import Attribute

    assertion_namespace = "urn:oasis:names:tc:SAML:2.0:assertion"
    nil_attribute = "{http://www.w3.org/2001/XMLSchema-instance}nil"
    root = ElementTree.fromstring(xml)
    matching_assertions = [
        item
        for item in root.iter(f"{{{assertion_namespace}}}Assertion")
        if item.get("ID") == assertion_id
    ]
    if len(matching_assertions) != 1:
        return []
    assertion = matching_assertions[0]
    recovered: list[Any] = []
    for attribute in assertion.iter(f"{{{assertion_namespace}}}Attribute"):
        wire_name = attribute.get("Name")
        if not wire_name:
            continue
        values: list[str] = []
        for value in attribute.findall(f"{{{assertion_namespace}}}AttributeValue"):
            nil = (value.get(nil_attribute) or "").lower()
            text = (value.text or "").strip()
            if nil in {"true", "1"} and text:
                values.append(text)
        if values:
            recovered.append(
                Attribute(
                    wire_name,
                    values=values,
                    name_format=attribute.get("NameFormat"),
                )
            )
    return recovered


def _validate_response_version(xml: str) -> None:
    """Translate pysaml2's response-version check to its public exceptions.

    The hardened native parser has already accepted this document before this
    helper runs, so using ElementTree to read the root attribute does not create
    a second, less-safe XML entry point.
    """
    from xml.etree import ElementTree

    value = ElementTree.fromstring(xml).get("Version")
    if value == "2.0":
        return
    try:
        version = tuple(int(part) for part in (value or "").split("."))
    except ValueError as exc:
        raise StatusError(f"invalid SAML response version {value!r}") from exc
    if version < (2, 0):
        raise RequestVersionTooLow(f"deprecated SAML response version {value}")
    raise StatusError(f"unsupported SAML response version {value!r}")


def _decrypted_assertions_for_time_error(
    response_xml: str, decryptor: SamlDecryptor
) -> list[Any]:
    """Decrypt assertions again so compatibility errors can inspect their times.

    This is called only after native parsing, signature verification, and profile
    validation have run. ElementTree therefore handles an already-accepted
    document, and the decrypted plaintext is parsed through pygamlastan's secure
    native assertion parser before any timestamp is inspected.
    """
    from xml.etree import ElementTree

    assertion_ns = "urn:oasis:names:tc:SAML:2.0:assertion"
    encryption_ns = "http://www.w3.org/2001/04/xmlenc#"
    try:
        root = ElementTree.fromstring(response_xml)
        assertions: list[Any] = []
        for wrapper in root.iter(f"{{{assertion_ns}}}EncryptedAssertion"):
            encrypted_data = wrapper.find(f"{{{encryption_ns}}}EncryptedData")
            if encrypted_data is None:
                continue
            plaintext = decryptor.decrypt(
                ElementTree.tostring(encrypted_data, encoding="unicode")
            )
            assertions.append(_xml.parse_assertion(plaintext))
    except (ElementTree.ParseError, SamlCryptoError, SamlXmlError):
        # Preserve the original validation failure when the diagnostic-only
        # second decryption cannot be completed.
        return []
    return assertions


def _raise_compat_time_error(
    parsed: Any,
    config: _security.SecurityConfig,
    *,
    assertions: list[Any] | None = None,
) -> None:
    """Raise pysaml2's dedicated exception for a native time-check failure.

    Native profile processing reports all validation failures through one
    ``SamlProfileError``. Inspecting the already-parsed typed timestamps keeps
    djangosaml2's exception contract without classifying errors from strings.
    This helper is called only after native validation has failed.
    """
    now = datetime.now(timezone.utc)
    skew = timedelta(seconds=config.clock_skew_seconds)

    for assertion in parsed.assertions if assertions is None else assertions:
        if now - assertion.issue_instant > (
            timedelta(seconds=config.max_assertion_age_seconds) + skew
        ):
            raise ResponseLifetimeExceed(
                "SAML assertion exceeds the configured maximum age"
            )

        conditions = assertion.conditions
        if conditions is not None:
            if (
                conditions.not_on_or_after is not None
                and now - skew >= conditions.not_on_or_after
            ):
                raise ResponseLifetimeExceed("SAML assertion conditions have expired")
            if conditions.not_before is not None and now + skew < conditions.not_before:
                raise ToEarly("SAML assertion conditions are not valid yet")

        subject = assertion.subject
        if subject is not None:
            for confirmation in subject.subject_confirmations:
                data = confirmation.subject_confirmation_data
                if data is None:
                    continue
                if (
                    data.not_on_or_after is not None
                    and now - skew >= data.not_on_or_after
                ):
                    raise ResponseLifetimeExceed(
                        "SAML subject confirmation has expired"
                    )
                if data.not_before is not None and now + skew < data.not_before:
                    raise ToEarly("SAML subject confirmation is not valid yet")

        for statement in assertion.authn_statements:
            if (
                statement.session_not_on_or_after is not None
                and now - skew >= statement.session_not_on_or_after
            ):
                raise ResponseLifetimeExceed("SAML authentication session has expired")


def _logout_deadline(value: Any) -> datetime | None:
    """Normalize pysaml2's common ``expire`` forms to an aware datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"invalid logout expiry {value!r}") from exc
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    raise TypeError(
        "logout expiry must be a datetime, epoch timestamp, ISO string, or None"
    )


def _nameid_key(
    name_id: Any,
) -> tuple[str, str | None, str | None, str | None, str | None] | None:
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
        # pysaml2's persisted NameID format omits empty optional attributes, so
        # an explicitly empty XML attribute and an absent attribute must
        # correlate to the same session subject during rolling migrations.
        return value if isinstance(value, str) and value else None

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


class _ScopedReplayCache:
    """Namespace opaque replay IDs without changing the cache protocol.

    Assertion and LogoutRequest IDs are unique only within their SAML trust
    context. The compat shim shares one backend across clients, so raw IDs must
    be scoped by message kind, local SP, and trusted IdP before they reach that
    backend. Compact JSON makes the tuple unambiguous; URL-safe base64 keeps the
    resulting key ASCII-only for Redis/database-backed protocol implementations.
    """

    _KEY_PREFIX = "pygamlastan-replay:v1:"

    def __init__(
        self,
        cache: Any,
        message_kind: str,
        sp_entity_id: str,
        expected_idp: str,
    ) -> None:
        self._cache = cache
        self._scope = (message_kind, sp_entity_id, expected_idp)

    def check_and_insert(self, message_id: str, expiry: datetime) -> bool:
        payload = json.dumps(
            (*self._scope, message_id),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        return self._cache.check_and_insert(self._KEY_PREFIX + encoded, expiry)

    def cleanup(self) -> None:
        self._cache.cleanup()


# Maximum accepted age (from IssueInstant) for a LogoutRequest that declares
# no NotOnOrAfter. validate_logout_request only bounds requests that DECLARE
# NotOnOrAfter, so without this limit a captured request would stay valid
# forever while any finite replay-cache entry eventually expires - breaking
# one-time use. Replay entries are retained past this window, so a request can
# never outlive its replay entry.
_LOGOUT_REQUEST_MAX_AGE = timedelta(hours=24)

# Evict expired replay entries periodically. gamlastan's check_and_insert only
# ever replaces the SAME expired ID and validation never calls cleanup(), so
# without this every accepted assertion/LogoutRequest ID would stay in the
# process-lifetime cache forever and a long-running SP would grow without
# bound. Cleanup is throttled PER CACHE (keyed by id()): a single process-wide
# timestamp would let traffic on one injected cache consume every cleanup slot
# while another cache is never cleaned. Entries are tiny and the table is
# pruned, so churning cache instances cannot grow it without bound; an id()
# reused after a cache is garbage-collected can at worst delay the new cache's
# first cleanup by one interval.
_REPLAY_CLEANUP_INTERVAL_SECONDS = 300.0
_replay_cleanup_lock = threading.Lock()
_replay_cleanup_times: dict[int, float] = {}


def _maybe_cleanup_replay_cache(cache: Any) -> None:
    now = time.monotonic()
    key = id(cache)
    with _replay_cleanup_lock:
        last = _replay_cleanup_times.get(key)
        if last is not None and now - last < _REPLAY_CLEANUP_INTERVAL_SECONDS:
            return
        _replay_cleanup_times[key] = now
        if len(_replay_cleanup_times) > 128:
            cutoff = now - _REPLAY_CLEANUP_INTERVAL_SECONDS
            for k in [k for k, t in _replay_cleanup_times.items() if t < cutoff]:
                del _replay_cleanup_times[k]
    try:
        cache.cleanup()
    except Exception:  # noqa: BLE001 - injected maintenance hook; retention is safe
        # Eviction is maintenance, not a security decision (retaining an entry
        # longer is safe), so a failing injected cache must not abort the
        # authentication/logout flow - but it must not fail silently either.
        import warnings

        warnings.warn(
            "replay cache cleanup() failed; expired entries were not evicted",
            stacklevel=2,
        )


class Saml2Client:
    """pysaml2-compatible SP client backed by pygamlastan.

    ``identity_cache`` and ``state_cache`` are real collaborators, not ignored
    constructor decoration: accepted identities are persisted for attribute
    display/logout, while outbound LogoutRequest IDs are persisted so a later
    response can be authenticated and correlated by a newly-created client.
    """

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
        self.identity_cache = identity_cache
        self.state_cache = state_cache
        # pysaml2 exposes its population facade as ``client.users``.  The cache
        # shim implements that read/write surface directly.
        self.users = identity_cache
        self.state = state_cache if state_cache is not None else {}
        self._signer: SamlSigner | None = None
        self._decryptor: SamlDecryptor | None = None
        decryption_key_files = [
            keypair["key_file"] for keypair in self.config.encryption_keypairs
        ]
        if not decryption_key_files and self.config.key_file:
            decryption_key_files.append(self.config.key_file)
        if decryption_key_files:
            keys = KeysManager()
            for key_file in decryption_key_files:
                try:
                    with open(key_file, "rb") as fh:
                        keys.add_key_pem(fh.read(), usage="decrypt")
                except OSError as exc:
                    raise ValueError(
                        f"configured encryption key {key_file!r} could not be read: {exc}"
                    ) from exc
            self._decryptor = SamlDecryptor(keys)
        # Default to the shared process-lifetime cache; ``replay_cache`` lets a
        # multi-process deployment supply a shared implementation (any object
        # with ``check_and_insert(id, expiry) -> bool`` and ``cleanup()``).
        self._replay_cache = (
            replay_cache if replay_cache is not None else _PROCESS_REPLAY_CACHE
        )

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

    def sso_location(
        self,
        entityid: str | None = None,
        binding: str = BINDING_HTTP_REDIRECT,
    ) -> str:
        """Return the IdP SSO endpoint for ``binding``.

        ``TypeError`` mirrors pysaml2's signal for an ambiguous IdP, while an
        explicitly selected but unsupported binding is reported as
        :class:`UnsupportedBinding`.
        """
        idp = entityid or self.config.only_idp()
        if idp is None:
            raise TypeError("Unable to determine which IdP to use")
        try:
            return self.config.single_sign_on_service(idp, binding)
        except ValueError as exc:
            raise UnsupportedBinding(str(exc)) from exc

    @staticmethod
    def _scoping_values(scoping: Any) -> tuple[int | None, list[str], list[str]]:
        """Convert mutable pysaml2 ``Scoping`` objects to typed native fields."""
        if scoping is None:
            return None, [], []
        proxy_count = getattr(scoping, "proxy_count", None)
        idp_list: list[str] = []
        container = getattr(scoping, "idp_list", None)
        entries = getattr(container, "idp_entry", []) if container is not None else []
        for entry in entries:
            provider_id = getattr(entry, "provider_id", None)
            if provider_id:
                idp_list.append(str(provider_id))
        requester_ids: list[str] = []
        for requester in getattr(scoping, "requester_id", []):
            value = getattr(requester, "text", requester)
            if value:
                requester_ids.append(str(value))
        return proxy_count, idp_list, requester_ids

    def create_authn_request(
        self,
        destination: str,
        binding: str = BINDING_HTTP_POST,
        sign: bool | None = None,
        sigalg: str | None = None,
        sign_alg: str | None = None,
        digest_alg: str | None = None,
        force_authn: str | bool | None = None,
        requested_authn_context: Any = None,
        nameid_format: str | None = None,
        allow_create: str | bool | None = None,
        scoping: Any = None,
        service_url_binding: str | None = None,
        **kwargs: Any,
    ) -> tuple[str, str]:
        """Create an AuthnRequest and return ``(request_id, XML)``.

        This is the lower-level API used by djangosaml2's custom HTTP-POST
        template. ``binding`` describes the requested response protocol, while
        ``service_url_binding`` optionally selects which configured ACS URL to
        include. When signing is enabled an enveloped XML signature is produced
        over this exact request document.
        """
        subject = kwargs.pop("subject", None)
        acs_url, _acs_binding = self.config.acs(service_url_binding or binding)
        force_value = self.config.force_authn if force_authn is None else force_authn
        force = str(force_value).lower() in ("true", "1", "yes")
        allow_value = self.config.allow_create if allow_create is None else allow_create
        allow = str(allow_value).lower() in ("true", "1", "yes")
        effective_nameid_format = (
            self.config.name_id_policy_format
            if nameid_format is None
            else nameid_format
        )
        native_allow_create = (
            None if effective_nameid_format == NAMEID_FORMAT_TRANSIENT else allow
        )

        context = (
            self.config.requested_authn_context
            if requested_authn_context is None
            else requested_authn_context
        )
        class_refs: list[str] | None = None
        comparison: str | None = None
        if isinstance(context, dict):
            reference = context.get("authn_context_class_ref")
            if isinstance(reference, str):
                class_refs = [reference]
            elif reference is not None:
                class_refs = [str(item) for item in reference]
            comparison = context.get("comparison", "exact")

        proxy_count, idp_list, requester_ids = self._scoping_values(scoping)
        options = _profiles.AuthnRequestOptions(
            sp_entity_id=self._require_entityid(),
            acs_url=acs_url,
            protocol_binding=binding,
            force_authn=force,
            name_id_format=effective_nameid_format,
            allow_create=native_allow_create,
            authn_context_class_refs=class_refs,
            authn_context_comparison=comparison,
            provider_name=kwargs.get("provider_name") or self.config.name,
            destination=destination,
            proxy_count=proxy_count,
            idp_list=idp_list,
            requester_ids=requester_ids,
            # pysaml2 uses letter-prefixed request IDs. djangosaml2 persists
            # them with an intentionally narrow legacy parser, so ask the
            # native builder for that interoperable form instead of rewriting
            # serialized XML after construction.
            request_id="id-" + secrets.token_hex(16),
            subject_name_id=(
                subject.name_id.to_core()
                if subject is not None and getattr(subject, "name_id", None) is not None
                else None
            ),
        )
        request = _profiles.create_authn_request(options)
        xml = request.to_xml()

        should_sign = self.config.authn_requests_signed if sign is None else bool(sign)
        if should_sign:
            signer = self._get_signer()
            xml = _sign_enveloped_request(
                xml,
                request.id,
                signer,
                sigalg or sign_alg or self.config.signing_algorithm,
                digest_alg or self.config.digest_algorithm,
            )
        return request.id, xml

    def prepare_for_authenticate(
        self,
        entityid: str | None = None,
        relay_state: str = "",
        binding: str = BINDING_HTTP_REDIRECT,
        sigalg: str | None = None,
        digest_alg: str | None = None,
        subject: Any = None,
        force_authn: str | bool | None = None,
        requested_authn_context: Any = None,
        sign: bool | None = None,
        response_binding: str = BINDING_HTTP_POST,
        **kwargs: Any,
    ) -> tuple[str, dict[str, Any]]:
        """Build and bind an AuthnRequest using pysaml2's return shape."""
        idp = entityid or self.config.only_idp()
        if idp is None:
            # pysaml2 raises TypeError here; eduID catches it to mean
            # "unable to know which IdP to use".
            raise TypeError("Unable to determine which IdP to use")

        effective_binding = binding
        try:
            sso_url = self.sso_location(idp, effective_binding)
        except UnsupportedBinding:
            # Some older configurations publish only a Redirect endpoint but
            # callers still ask the binding layer for POST first.  Preserve
            # pysaml2's endpoint fallback; djangosaml2 normally detects and
            # switches the binding itself before reaching this method.
            effective_binding = BINDING_HTTP_REDIRECT
            sso_url = self.sso_location(idp, effective_binding)

        # The response protocol and the binding used to select the ACS URL are
        # independent pysaml2 options. Most callers leave service_url_binding
        # unset, in which case create_authn_request uses response_binding for
        # both values.
        service_url_binding = kwargs.pop("service_url_binding", None)
        session_id, xml = self.create_authn_request(
            sso_url,
            binding=response_binding,
            service_url_binding=service_url_binding,
            sign=False,
            force_authn=force_authn,
            requested_authn_context=requested_authn_context,
            subject=subject,
            sigalg=sigalg,
            digest_alg=digest_alg,
            **kwargs,
        )

        rs = relay_state or None
        should_sign = self.config.authn_requests_signed if sign is None else bool(sign)
        if effective_binding == BINDING_HTTP_REDIRECT:
            signer = self._get_signer() if should_sign else None
            effective_sigalg = sigalg or self.config.signing_algorithm
            if signer is not None and effective_sigalg is None:
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
        elif effective_binding == BINDING_HTTP_POST:
            if should_sign:
                signer = self._get_signer()
                xml = _sign_enveloped_request(
                    xml,
                    session_id,
                    signer,
                    sigalg or self.config.signing_algorithm,
                    digest_alg or self.config.digest_algorithm,
                )
            html = _bindings.post_encode(
                xml.encode("utf-8"), True, sso_url, relay_state=rs
            )
            return session_id, _post_http_info(sso_url, html)
        raise UnsupportedBinding(
            f"unsupported binding for AuthnRequest: {effective_binding}"
        )

    # -- Response processing ----------------------------------------------

    def parse_authn_request_response(
        self,
        response: str,
        binding: str,
        outstanding: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> AuthnResponse:
        """Decode, authenticate, validate, and adapt an IdP AuthnResponse."""
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

        _validate_response_version(xml)

        in_response_to = parsed.in_response_to
        if outstanding is not None and in_response_to not in outstanding:
            raise UnsolicitedResponse(
                f"InResponseTo {in_response_to!r} not in outstanding queries"
            )

        # Recipient/ACS check uses the ACS for the binding this response actually
        # arrived over (config.acs falls back to the first configured ACS when the
        # exact binding is absent), rather than assuming HTTP-POST.
        acs_url, _ = self.config.acs(binding)
        expected_idp = kwargs.get("expected_idp")
        expected_idps = kwargs.get("expected_idps")
        if (
            expected_idp is None
            and expected_idps is not None
            and in_response_to is not None
        ):
            expected_idp = expected_idps.get(in_response_to)
        expected_idp = expected_idp or self.config.only_idp()
        if expected_idp is None:
            # The legacy outstanding-query mapping stores only the return URL,
            # not the IdP selected for the request. Trusting the response's
            # claimed issuer here would let any configured IdP answer another
            # IdP's outstanding request. Require the caller to supply the
            # request-correlated entity ID when the configuration is ambiguous.
            raise ValueError(
                "Cannot determine the IdP targeted by this outstanding request; "
                "pass expected_idp=<entity id>"
            )

        # Both branches below insert into the replay cache; give expired
        # entries a periodic (throttled) chance to be evicted first.
        _maybe_cleanup_replay_cache(self._replay_cache)
        scoped_replay_cache = _ScopedReplayCache(
            self._replay_cache,
            "assertion",
            sp_entity_id,
            expected_idp,
        )

        if self.config.want_response_signed or self.config.want_assertions_signed:
            # Use the safe-by-construction entry point: process_response_verified
            # performs XML-DSig verification over the EXACT bytes internally and
            # feeds only the cryptographically verified IDs into validation, so
            # there is no verified_signed_ids to thread (and no chance to mis-wire
            # it). `want_response_signed` maps to a required Response-envelope
            # signature; it does not imply direct Assertion signatures.
            cfg = _security.SecurityConfig()
            cfg.clock_skew_seconds = self.config.accepted_time_diff
            cfg.require_signed_assertions = self.config.want_assertions_signed
            cfg.require_signed_responses = self.config.want_response_signed
            cfg.require_encrypted_assertions = False
            try:
                signing_certs = self.config.idp_signing_certs(expected_idp)
            except ValueError as exc:
                raise MissingKey(str(exc)) from exc
            verifier = SamlVerifier.from_certs(signing_certs)
            try:
                result = _profiles.process_response_verified(
                    xml,
                    verifier,
                    cfg,
                    sp_entity_id,
                    acs_url,
                    expected_idp,
                    expected_request_id=in_response_to,
                    replay_cache=scoped_replay_cache,
                    decryptor=self._decryptor,
                    unsafe_no_persistent_id_store=True,
                )
            except SamlCryptoError as crypto_error:
                raise SignatureError(
                    f"SAML response is not verified: {crypto_error}"
                ) from crypto_error
            except Exception as e:
                if not parsed.is_success():
                    self._raise_on_failed_status(parsed)
                assertions = None
                if (
                    not parsed.assertions
                    and parsed.encrypted_assertion_count
                    and self._decryptor is not None
                ):
                    assertions = _decrypted_assertions_for_time_error(
                        xml, self._decryptor
                    )
                _raise_compat_time_error(parsed, cfg, assertions=assertions)
                raise AssertionError(f"SAML response validation failed: {e}") from e
        else:
            # Unsigned responses are only acceptable in dev/test, where the
            # settings explicitly set want_response_signed=False.
            self._raise_on_failed_status(parsed)
            cfg = _security.SecurityConfig.permissive()
            cfg.clock_skew_seconds = self.config.accepted_time_diff
            try:
                result = _profiles.process_response(
                    parsed,
                    cfg,
                    sp_entity_id,
                    acs_url,
                    expected_idp,
                    expected_request_id=in_response_to,
                    verified_signed_ids=[],
                    replay_cache=scoped_replay_cache,
                    unsafe_no_persistent_id_store=True,
                )
            except Exception as e:
                _raise_compat_time_error(parsed, cfg)
                raise AssertionError(f"SAML response processing failed: {e}") from e

        assertion = getattr(result, "assertion", None)
        if assertion is None:
            assertion = next(
                (item for item in parsed.assertions if item.id == result.assertion_id),
                None,
            )
        if assertion is None:
            raise AssertionError(
                f"processed assertion {result.assertion_id!r} is absent from response"
            )
        came_from = outstanding.get(in_response_to) if outstanding is not None else None
        wrapped = AuthnResponse(
            result,
            in_response_to,
            assertion=assertion,
            came_from=came_from,
            legacy_attributes=_legacy_nil_attributes(xml, result.assertion_id),
            allow_unknown_attributes=self.config.allow_unknown_attributes,
        )
        if self.identity_cache is not None:
            session_info = wrapped.session_info()
            self.identity_cache.set(
                session_info["name_id"],
                session_info["issuer"],
                session_info,
                session_info["not_on_or_after"],
            )
        return wrapped

    @staticmethod
    def _raise_on_failed_status(parsed: Any) -> None:
        """Translate common SAML status codes to pysaml2 exception classes."""
        if not parsed.is_success():
            status_code = parsed.status.status_code
            values = []
            while status_code is not None:
                values.append(status_code.value)
                status_code = status_code.sub_status
            message = f"SAML response status not Success: {' / '.join(values)}"
            if any(value.endswith(":AuthnFailed") for value in values):
                raise StatusAuthnFailed(message)
            if any(value.endswith(":NoAuthnContext") for value in values):
                raise StatusNoAuthnContext(message)
            if any(value.endswith(":RequestDenied") for value in values):
                raise StatusRequestDenied(message)
            raise StatusError(message)

    # -- Single Logout ----------------------------------------------------

    def global_logout(
        self,
        name_id: NameID | str,
        reason: str = "",
        expire: Any = None,
        sign: Any = None,
        sign_alg: str | None = None,
        digest_alg: str | None = None,
        state_data: dict[str, Any] | None = None,
    ) -> dict[str, tuple[str, dict[str, Any]]]:
        """Begin SP-initiated logout for every issuer holding identity data.

        The mapping follows pysaml2 exactly: each value is
        ``(binding, http_info)``. Session-backed identity data determines the
        preferred peers; configuration and metadata are the fallback.
        """
        if isinstance(name_id, str):
            name_id = decode(name_id)
        if _nameid_key(name_id) is None:
            raise ValueError(
                "global_logout requires a NameID with a non-empty identifier"
            )
        candidate_idps: list[str] = []
        if self.users is not None:
            issuers = getattr(self.users, "issuers_of_info", None)
            if callable(issuers):
                candidate_idps = list(issuers(name_id))
        if not candidate_idps:
            candidate_idps = list(self.config.idp) + [
                entity_id
                for entity_id, entity in self.config.metadata.items()
                if entity.is_idp() and entity_id not in self.config.idp
            ]
        return self.do_logout(
            name_id,
            candidate_idps,
            reason,
            expire,
            sign=sign,
            sign_alg=sign_alg,
            digest_alg=digest_alg,
            state_data=state_data,
        )

    def do_logout(
        self,
        name_id: NameID,
        entity_ids: list[str],
        reason: str,
        expire: Any,
        sign: bool | None = None,
        expected_binding: str | None = None,
        sign_alg: str | None = None,
        digest_alg: str | None = None,
        **kwargs: Any,
    ) -> dict[str, tuple[str, dict[str, Any]]]:
        """Create bound LogoutRequests for selected IdPs.

        djangosaml2 subclasses this method to force a preferred binding. Only
        browser bindings are returned; the shim never performs hidden SOAP I/O.
        """
        sp_entity_id = self._require_entityid()
        state_data = kwargs.pop("state_data", None)
        requested_relay_state = kwargs.pop("relay_state", None)
        deadline = _logout_deadline(expire)
        if deadline is not None and deadline <= datetime.now(timezone.utc):
            raise LogoutError("the requested logout expiry has already passed")
        core_name_id = name_id.to_core()
        should_sign = self.config.logout_requests_signed if sign is None else bool(sign)
        signer = self._get_signer() if should_sign else None
        signature_algorithm = sign_alg or self.config.signing_algorithm
        if signer is not None and signature_algorithm is None:
            signature_algorithm = signer.signature_method_uri()

        preferred = list(self.config.preferred_binding["single_logout_service"])
        candidates = []
        for candidate in ([expected_binding] if expected_binding else []) + preferred:
            if (
                candidate in (BINDING_HTTP_REDIRECT, BINDING_HTTP_POST)
                and candidate not in candidates
            ):
                candidates.append(candidate)

        selected_endpoints: list[tuple[str, str, str]] = []
        unhandled: list[str] = []
        for idp in entity_ids:
            selected: tuple[str, str] | None = None
            for candidate in candidates:
                try:
                    selected = (
                        candidate,
                        self.config.single_logout_service(idp, candidate),
                    )
                    break
                except ValueError:
                    continue
            if selected is None:
                unhandled.append(idp)
            else:
                selected_endpoints.append((idp, *selected))
        if unhandled:
            raise LogoutError(f"no configured SLO endpoint for {unhandled!r}")

        responses: dict[str, tuple[str, dict[str, Any]]] = {}
        for idp, binding, slo_url in selected_endpoints:
            session_indexes: list[str] | None = None
            if self.users is not None:
                getter = getattr(self.users, "get_info_from", None)
                if callable(getter):
                    try:
                        info = getter(name_id, idp, False) or {}
                    except KeyError:
                        info = {}
                    session_index = info.get("session_index")
                    session_indexes = [session_index] if session_index else None

            options = _logout.SpLogoutRequestOptions(
                sp_entity_id=sp_entity_id,
                name_id=core_name_id,
                session_indexes=session_indexes,
                reason=reason or None,
                destination=slo_url,
                not_on_or_after=deadline,
            )
            try:
                request = _logout.create_sp_logout_request(options)
            except Exception as exc:
                raise LogoutError(
                    f"could not create LogoutRequest for {idp}: {exc}"
                ) from exc

            xml = request.to_xml()
            relay_state = (
                requested_relay_state
                if requested_relay_state is not None
                else request.id
            )
            if binding == BINDING_HTTP_REDIRECT:
                url = _bindings.redirect_encode(
                    xml.encode("utf-8"),
                    True,
                    slo_url,
                    relay_state=relay_state,
                    signer=signer,
                    sig_alg=signature_algorithm,
                )
                http_info = _redirect_http_info(url)
            elif binding == BINDING_HTTP_POST:
                if signer is not None:
                    xml = _sign_enveloped_request(
                        xml,
                        request.id,
                        signer,
                        signature_algorithm,
                        digest_alg or self.config.digest_algorithm,
                    )
                html = _bindings.post_encode(
                    xml.encode("utf-8"), True, slo_url, relay_state=relay_state
                )
                http_info = _post_http_info(slo_url, html)
            else:
                continue

            # A later request creates a fresh client around the same session
            # adapter. Persist local state needed to authenticate correlation.
            self.state[request.id] = {
                "entity_id": idp,
                "operation": "SLO",
                "name_id": code(name_id),
                "binding": binding,
                "relay_state": relay_state,
                "reason": reason,
                # Django's default JSON session serializer cannot persist a
                # datetime object; keep the state cache transport-neutral.
                "not_on_or_after": deadline.isoformat() if deadline else None,
                "sign": should_sign,
                "data": dict(state_data or {}),
            }
            responses[idp] = (binding, http_info)

        sync = getattr(self.state, "sync", None)
        if callable(sync):
            sync()
        return responses

    def _verify_logout_response_signature(
        self,
        xml: str,
        parsed: Any,
        expected_idp: str,
        binding: str,
        kwargs: dict[str, Any],
    ) -> None:
        """Verify an enveloped or detached signature over a LogoutResponse."""
        try:
            certs = self.config.idp_signing_certs(expected_idp)
        except ValueError as exc:
            raise MissingKey(str(exc)) from exc
        if not certs:
            raise MissingKey(f"no signing certificate configured for {expected_idp!r}")
        try:
            verifiers = [SamlVerifier.from_cert(cert) for cert in certs]
        except Exception as exc:
            raise MissingKey(
                f"invalid signing certificate configured for {expected_idp!r}: {exc}"
            ) from exc
        verified = False

        sig_alg = kwargs.get("sig_alg") or kwargs.get("sigalg")
        signature = kwargs.get("signature")
        signed_query = kwargs.get("signed_query")
        if binding == BINDING_HTTP_REDIRECT and any((sig_alg, signature, signed_query)):
            if not (sig_alg and signature and signed_query):
                raise SignatureError(
                    "sig_alg, signature and signed_query are all required for Redirect verification"
                )
            params = {
                urllib.parse.unquote(key): urllib.parse.unquote(value)
                for key, _, value in (
                    part.partition("=") for part in signed_query.split("&")
                )
            }
            if params.get("SigAlg") != sig_alg or "SAMLResponse" not in params:
                raise SignatureError(
                    "signed query does not describe this LogoutResponse"
                )
            try:
                query_xml = self._decode_message(
                    params["SAMLResponse"], BINDING_HTTP_REDIRECT
                )
            except Exception as exc:
                raise SignatureError(
                    f"could not decode signed Redirect LogoutResponse: {exc}"
                ) from exc
            if query_xml != xml:
                raise SignatureError("signed query carries a different LogoutResponse")
            try:
                raw_signature = base64.b64decode(signature, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise SignatureError(
                    f"invalid Redirect signature encoding: {exc}"
                ) from exc
            for verifier in verifiers:
                try:
                    if verifier.verify_redirect_query(
                        signed_query.encode("utf-8"), raw_signature, sig_alg
                    ):
                        verified = True
                        break
                except SamlCryptoError:
                    continue

        # Requiring the root ID among verified references prevents a wrapped
        # sibling element from authenticating the consumed LogoutResponse.
        for verifier in verifiers:
            try:
                results = verifier.verify_all_enveloped(xml)
            except SamlCryptoError:
                continue
            if results and all(result.is_valid() for result in results):
                signed_ids = {
                    reference
                    for result in results
                    for reference in result.signed_reference_ids()
                }
                if parsed.id in signed_ids:
                    verified = True
                    break
        if not verified:
            raise SignatureError("LogoutResponse signature is missing or invalid")

    def parse_logout_request_response(
        self, response: str, binding: str = BINDING_HTTP_REDIRECT, **kwargs: Any
    ) -> LogoutResponse:
        """Authenticate, correlate, and adapt an IdP LogoutResponse.

        Correlation is enforced whenever a state cache was supplied. Signed
        production configurations additionally require a detached Redirect
        signature or an enveloped XML signature.
        """
        try:
            xml = self._decode_message(response, binding)
            parsed = _xml.parse_logout_response(xml)
        except Exception as exc:
            raise StatusError(f"could not parse LogoutResponse: {exc}") from exc

        request_id = parsed.in_response_to
        state = self.state.get(request_id) if request_id is not None else None
        if self.state_cache is not None and state is None:
            raise StatusError(
                f"LogoutResponse InResponseTo {request_id!r} is not outstanding"
            )
        expected_idp = kwargs.get("expected_idp")
        if expected_idp is None and state is not None:
            expected_idp = state.get("entity_id")
        expected_idp = expected_idp or self.config.only_idp()
        if expected_idp is None:
            raise StatusError("cannot determine the IdP for LogoutResponse")
        issuer = parsed.issuer.value if parsed.issuer is not None else None
        if issuer != expected_idp:
            raise StatusError(
                f"LogoutResponse issuer {issuer!r} does not match {expected_idp!r}"
            )

        # The hardened native parser already rejected DTD/entity constructs.
        # ElementTree reads only a root attribute missing from the native value.
        import xml.etree.ElementTree as ET

        destination = ET.fromstring(xml).attrib.get("Destination")
        if destination is not None:
            local_destinations = {
                url
                for url, endpoint_binding in self.config.slo_endpoints
                if endpoint_binding == binding
            }
            if destination not in local_destinations:
                raise StatusError(
                    f"LogoutResponse Destination {destination!r} is not a local SLO endpoint"
                )
        if self.config.want_logout_response_signed:
            try:
                self._verify_logout_response_signature(
                    xml, parsed, expected_idp, binding, kwargs
                )
            except (MissingKey, SignatureError) as exc:
                raise StatusError(
                    f"LogoutResponse signature verification failed: {exc}"
                ) from exc
        if not parsed.is_success():
            raise StatusError("LogoutResponse status is not Success")
        relay_state = kwargs.get("relay_state")
        if state is not None and request_id is not None:
            stored_relay_state = state.get("relay_state")
            if stored_relay_state is not None:
                relay_state_matches = relay_state == stored_relay_state
            else:
                relay_state_matches = isinstance(relay_state, str) and (
                    _matches_legacy_logout_relay_state(
                        request_id, relay_state, self.config.raw.get("secret")
                    )
                )
            if not relay_state_matches:
                raise StatusError(
                    "LogoutResponse RelayState does not match the outstanding request"
                )
        if state is not None and request_id is not None:
            marker = object()
            consumed = self.state.pop(request_id, marker)
            if consumed is marker:
                raise StatusError("LogoutResponse state was already consumed")
            sync = getattr(self.state, "sync", None)
            if callable(sync):
                sync()
        return LogoutResponse(
            True,
            in_response_to=request_id,
            state=dict(state.get("data", {})) if state is not None else {},
        )

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
        expected_idp = kwargs.get("expected_idp") or self.config.only_idp()
        # Decode, parse, verify, and validate inside one guard so transport/XML
        # failures (bad base64/DEFLATE/UTF-8, non-XML), signature failures, and
        # validation failures all surface uniformly as
        # ValueError("invalid LogoutRequest: ..."). validate_logout_request
        # requires the Issuer to equal the trusted IdP, proof of signature
        # verification, a present NameID, and an unexpired NotOnOrAfter (default
        # 180s skew); when a Destination is present, the shim additionally
        # requires it to name one of this SP's configured SLO endpoints for the
        # received binding - so an unsigned, misattributed, misaddressed, or
        # stale LogoutRequest cannot force-log out a session.
        try:
            xml = self._decode_message(request, binding)
            parsed = _xml.parse_logout_request(xml)
            if expected_idp is None:
                issuer = parsed.issuer.value if parsed.issuer is not None else None
                known_idps = set(self.config.idp) | set(self.config.metadata)
                if issuer not in known_idps:
                    raise ValueError(
                        "Cannot determine a configured IdP for LogoutRequest processing"
                    )
                # As with AuthnResponse processing, the issuer selects only a
                # configured trust anchor. Signature verification below must
                # authenticate the exact request before that issuer is trusted.
                expected_idp = issuer
            # Destination binding: a present Destination must name one of THIS
            # SP's configured SLO endpoints for the received binding. Without
            # this, a request validly signed by the trusted IdP but addressed
            # to a different SP or binding would pass the
            # issuer/signature/subject checks and destroy a session here.
            # Upstream validate_logout_request does not check Destination, and
            # the shim never sees the actual request URL, so the configured
            # (URL, binding) pairs are the local ground truth. Deployments that
            # accept multiple bindings at one URL must configure that URL for
            # each binding.
            if parsed.destination is not None:
                local_slo = {
                    url
                    for url, endpoint_binding in self.config.slo_endpoints
                    if endpoint_binding == binding
                }
                if parsed.destination not in local_slo:
                    raise ValueError(
                        f"LogoutRequest Destination {parsed.destination!r} is "
                        "not a configured SLO endpoint of this SP for "
                        f"binding {binding!r}"
                    )
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
            raise ValueError("LogoutRequest NameID does not match the session NameID")
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
        # Reject an IssueInstant beyond the validation clock skew in the
        # future before selecting either expiry branch: upstream
        # validate_logout_request checks only NotOnOrAfter, so a far-future
        # IssueInstant would otherwise pass the age check and pin a replay
        # entry expiring 24h after that future instant - unbounded cache
        # retention for what may be (in the no-certificate fallback) an
        # unauthenticated request.
        if parsed.issue_instant - now > timedelta(seconds=180):
            raise ValueError(
                "LogoutRequest IssueInstant is in the future beyond the "
                "accepted clock skew"
            )
        if parsed.not_on_or_after is not None:
            # Bound the request-declared validity window the same way the
            # no-NotOnOrAfter branch bounds lifetime: a date years ahead would
            # pin a replay entry until then, letting unique requests (in the
            # unsigned development fallback, unauthenticated ones) grow the
            # process-wide cache without bound.
            if parsed.not_on_or_after - now > _LOGOUT_REQUEST_MAX_AGE:
                raise ValueError(
                    "LogoutRequest NotOnOrAfter is further ahead than the "
                    f"maximum accepted validity window ({_LOGOUT_REQUEST_MAX_AGE})"
                )
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
        scoped_replay_cache = _ScopedReplayCache(
            self._replay_cache,
            "logout-request",
            sp_entity_id,
            expected_idp,
        )
        if not scoped_replay_cache.check_and_insert(parsed.id, replay_expiry):
            raise ValueError(
                "LogoutRequest replay detected: this request ID was already processed"
            )
        issuer = parsed.issuer.value if parsed.issuer is not None else expected_idp
        response_bindings = {
            BINDING_HTTP_POST: [BINDING_HTTP_POST, BINDING_HTTP_REDIRECT],
            BINDING_HTTP_REDIRECT: [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST],
        }.get(binding)
        if response_bindings is None:
            raise UnsupportedBinding(
                f"unsupported binding for LogoutResponse: {binding}"
            )
        response_binding = None
        slo_url = None
        for candidate in response_bindings:
            try:
                slo_url = self.config.single_logout_response_service(issuer, candidate)
                response_binding = candidate
                break
            except ValueError:
                continue
        if response_binding is None or slo_url is None:
            raise UnsupportedBinding(
                f"no supported SingleLogoutService response endpoint for {issuer!r}"
            )
        resp = _logout.create_logout_response_success(
            sp_entity_id, parsed.id, destination=slo_url
        )
        response_signer = (
            self._get_signer() if self.config.logout_responses_signed else None
        )
        xml = resp.to_xml()
        if response_binding == BINDING_HTTP_POST:
            if response_signer is not None:
                xml = _sign_enveloped_request(
                    xml,
                    resp.id,
                    response_signer,
                    self.config.signing_algorithm,
                    self.config.digest_algorithm,
                )
            html = _bindings.post_encode(
                xml.encode("utf-8"),
                False,
                slo_url,
                relay_state=relay_state or None,
            )
            return _post_http_info(slo_url, html)

        response_sig_alg = None
        if response_signer is not None:
            response_sig_alg = (
                self.config.signing_algorithm or response_signer.signature_method_uri()
            )
        url = _bindings.redirect_encode(
            xml.encode("utf-8"),
            False,
            slo_url,
            relay_state=relay_state or None,
            signer=response_signer,
            sig_alg=response_sig_alg,
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
        transport layer) there is no trust anchor to verify against. That case
        FAILS CLOSED unless the deployment explicitly opts in via
        ``allow_unsigned_logout_requests`` in the SP settings (mirroring the
        ready IdP's ``allow_unauthenticated_backchannel`` escape hatch); with
        the opt-in the request is accepted with a warning. A silently missing
        production certificate must never downgrade this session-destroying
        endpoint to unsigned requests. Configure IdP metadata with a signing
        certificate to enforce LogoutRequest signatures.
        """
        # Extract the detached-signature material and enforce tuple
        # completeness BEFORE any certificate lookup: an incomplete tuple
        # (e.g. SigAlg with a stripped Signature) is an error everywhere,
        # including the no-certificate development fallback below - otherwise
        # a known IdP without metadata keys could have a partial tuple
        # accepted as "unsigned". A genuinely unsigned request (no signature
        # fields at all) may still reach the fallback.
        sig_alg = kwargs.get("sig_alg") or kwargs.get("sigalg")
        signature = kwargs.get("signature")
        signed_query = kwargs.get("signed_query")
        if (
            binding == BINDING_HTTP_REDIRECT
            and any((sig_alg, signature, signed_query))
            and not (sig_alg and signature and signed_query)
        ):
            raise ValueError(
                "incomplete redirect signature: sig_alg, signature and "
                "signed_query must all be supplied together"
            )

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
            # Fail closed by default: a missing production certificate must
            # not silently turn the session-destroying endpoint into one that
            # accepts unsigned requests. The unverified path requires the
            # explicit allow_unsigned_logout_requests opt-in.
            if not self.config.allow_unsigned_logout_requests:
                raise ValueError(
                    f"no signing certificate configured for IdP {expected_idp!r}; "
                    "refusing to accept an unverified LogoutRequest. Configure "
                    "IdP metadata with a signing certificate, or explicitly set "
                    "allow_unsigned_logout_requests=True in the SP settings "
                    "(development only)."
                ) from None
            import warnings

            warnings.warn(
                "No signing certificate configured for IdP "
                f"{expected_idp!r}; accepting the LogoutRequest without "
                "signature verification because allow_unsigned_logout_requests "
                "is enabled. Configure IdP metadata with a signing certificate "
                "to enforce LogoutRequest signatures.",
                stacklevel=2,
            )
            return True
        verifiers = [SamlVerifier.from_cert(cert) for cert in certs]
        verified = False

        # HTTP-Redirect binding: detached signature over the query string. The
        # web handler must forward the SigAlg/Signature parameters and the exact
        # signed portion of the query it received (tuple completeness was
        # enforced above, before the certificate lookup). Any published
        # (rollover) certificate may have produced the signature.
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
            query_bytes = signed_query.encode("utf-8")
            # verify_redirect_query can RAISE for a particular certificate
            # (e.g. a key-type/algorithm mismatch on a retired rollover key)
            # instead of returning False, so a plain any() would abort at the
            # first such certificate and never reach a later valid one. Try
            # every published certificate; fail only after all were attempted.
            redirect_ok = False
            redirect_error: Exception | None = None
            for verifier in verifiers:
                try:
                    if verifier.verify_redirect_query(
                        query_bytes, raw_signature, sig_alg
                    ):
                        redirect_ok = True
                        break
                except SamlCryptoError as e:
                    redirect_error = e
            if not redirect_ok:
                raise ValueError(
                    "LogoutRequest redirect signature is invalid"
                ) from redirect_error
            verified = True

        # Enveloped XML-DSig (POST binding, or a redirect request that also
        # carries an enveloped signature). Bind the verified reference to the
        # request ID so a wrapped signature over a sibling object cannot count.
        if parsed.has_signature:
            last_error: Exception | None = None
            for verifier in verifiers:
                try:
                    results = verifier.verify_all_enveloped(xml)
                except SamlCryptoError as e:
                    # Not signed by this (rollover) certificate; try the next.
                    last_error = e
                    continue
                # verify_all_enveloped can RETURN an invalid VerifyResult
                # rather than raising (e.g. a tampered SignatureValue), so
                # require at least one result and that every signature present
                # verifies under this certificate before its reference IDs
                # count for anything.
                invalid = [r for r in results if not r.is_valid()]
                if not results or invalid:
                    reasons = "; ".join(
                        r.reason or "invalid signature" for r in invalid
                    )
                    last_error = ValueError(
                        "LogoutRequest XML signature is invalid"
                        + (f": {reasons}" if reasons else ": no signature found")
                    )
                    continue
                signed_ids = [
                    ref for result in results for ref in result.signed_reference_ids()
                ]
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
