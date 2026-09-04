"""``saml2.config`` shim: :class:`SPConfig` reads the existing eduID
``saml2_settings.py`` dict and exposes just what the client/metadata shims need.

Only the keys eduID actually sets are interpreted. Legacy-only keys such as
``xmlsec_binary`` and ``attribute_map_dir`` are accepted and ignored, while
organization and contact information are retained for generated SP metadata.
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from pygamlastan import metadata as _md
from pygamlastan.core import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from pygamlastan.crypto import SamlVerifier

from .mdstore import MetadataStore, SourceNotFound


def _as_bool(value: Any) -> bool:
    """Parse pysaml2-style boolean values without treating ``"false"`` as true."""
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off", ""}:
            return False
    return bool(value)


_MAX_REMOTE_METADATA_BYTES = 32 * 1024 * 1024


class _HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        if urllib.parse.urlsplit(newurl).scheme.lower() != "https":
            raise SourceNotFound("remote metadata redirect must use HTTPS")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class SPConfig:
    """A minimal SP configuration parsed from an eduID-style settings dict."""

    def __init__(self) -> None:
        self.entityid: str = ""
        self.name: str | None = None
        # endpoints: list of (url, binding)
        self.acs_endpoints: list[tuple[str, str]] = []
        self.slo_endpoints: list[tuple[str, str]] = []
        # idp config: {entity_id: {"single_sign_on_service": {binding: url},
        #                          "single_logout_service": {binding: url}}}
        self.idp: dict[str, dict[str, dict[str, str]]] = {}
        self.want_response_signed: bool = True
        self.want_assertions_signed: bool = False
        self.want_logout_response_signed: bool = False
        self.authn_requests_signed: bool = False
        self.logout_requests_signed: bool = False
        self.logout_responses_signed: bool = False
        self.force_authn: bool = False
        self.allow_create: bool = False
        self.allow_unknown_attributes: bool = False
        self.allow_unsolicited: bool = False
        self.name_id_format: str | list[str] | None = None
        self.name_id_policy_format: str | None = None
        self.requested_authn_context: Any = None
        self.signing_algorithm: str | None = None
        self.digest_algorithm: str | None = None
        self.accepted_time_diff: int = 0
        # Explicit development opt-out: accept an unverified LogoutRequest for
        # an IdP that publishes no signing certificate. This is independent of
        # response-signature policy and stays off unless directly configured.
        self.allow_unsigned_logout_requests: bool = False
        self.key_file: str | None = None
        self.cert_file: str | None = None
        self.metadata_key_usage: str = "both"
        self.encryption_keypairs: list[dict[str, str]] = []
        # parsed metadata EntityDescriptors keyed by entity id
        self.metadata = MetadataStore()
        self.preferred_binding = {
            "single_logout_service": [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
        }
        self._sp: dict[str, Any] = {}
        self.raw: dict[str, Any] = {}
        self.required_attributes: list[str] = []
        self.optional_attributes: list[str] = []
        self.organization: dict[str, Any] = {}
        self.contact_person: list[dict[str, Any]] = []
        self._signature_policy_explicit = False

    # -- loading ----------------------------------------------------------

    def load(self, conf: dict[str, Any]) -> SPConfig:
        """Load a pysaml2-style service-provider configuration mapping."""
        self.raw = dict(conf)
        self.entityid = str(conf.get("entityid") or "")
        sp = conf.get("service", {}).get("sp", {})
        self._sp = dict(sp)
        self.name = sp.get("name")
        self._signature_policy_explicit = any(
            key in sp
            for key in (
                "want_response_signed",
                "want_assertions_signed",
                "want_logout_response_signed",
            )
        )
        self.required_attributes = list(sp.get("required_attributes", []))
        self.optional_attributes = list(sp.get("optional_attributes", []))
        self.organization = dict(conf.get("organization", {}))
        self.contact_person = list(conf.get("contact_person", []))

        endpoints = sp.get("endpoints", {})
        self.acs_endpoints = [
            tuple(e) for e in endpoints.get("assertion_consumer_service", [])
        ]
        self.slo_endpoints = [
            tuple(e) for e in endpoints.get("single_logout_service", [])
        ]

        self.idp = dict(sp.get("idp", {}))
        # The shim deliberately defaults to signed AuthnResponses. Deployments
        # accepting unsigned test responses must opt out in their SP settings.
        self.want_response_signed = _as_bool(sp.get("want_response_signed", True))
        self.want_assertions_signed = _as_bool(sp.get("want_assertions_signed", False))
        # pysaml2 treats logout-response signing as its own setting; requiring
        # signed AuthnResponses must not silently change the SLO contract.
        self.want_logout_response_signed = _as_bool(
            sp.get("want_logout_response_signed", False)
        )
        self.authn_requests_signed = _as_bool(sp.get("authn_requests_signed", False))
        self.logout_requests_signed = _as_bool(sp.get("logout_requests_signed", False))
        self.logout_responses_signed = _as_bool(
            sp.get("logout_responses_signed", False)
        )
        self.force_authn = _as_bool(sp.get("force_authn", False))
        self.allow_create = _as_bool(
            sp.get("allow_create", sp.get("name_id_format_allow_create", False))
        )
        self.allow_unknown_attributes = _as_bool(
            sp.get(
                "allow_unknown_attributes", conf.get("allow_unknown_attributes", False)
            )
        )
        self.allow_unsolicited = _as_bool(sp.get("allow_unsolicited", False))
        self.name_id_format = sp.get("name_id_format")
        self.name_id_policy_format = sp.get("name_id_policy_format")
        self.requested_authn_context = sp.get("requested_authn_context")
        self.signing_algorithm = sp.get("signing_algorithm")
        self.digest_algorithm = sp.get("digest_algorithm")
        self.accepted_time_diff = int(conf.get("accepted_time_diff") or 0)
        self.allow_unsigned_logout_requests = _as_bool(
            sp.get("allow_unsigned_logout_requests", False)
        )

        # Private attributes are part of the de-facto pysaml2 configuration
        # contract consumed by djangosaml2.
        self._sp_authn_requests_signed = self.authn_requests_signed
        self._sp_signing_algorithm = self.signing_algorithm
        self._sp_digest_algorithm = self.digest_algorithm
        self._sp_force_authn = self.force_authn
        self._sp_allow_create = self.allow_create
        self._sp_name_id_policy_format = self.name_id_policy_format

        self.key_file = conf.get("key_file")
        self.cert_file = conf.get("cert_file")
        metadata_key_usage = conf.get("metadata_key_usage", "both")
        if metadata_key_usage not in {"signing", "encryption", "both"}:
            raise ValueError(
                "metadata_key_usage must be 'signing', 'encryption', or 'both'"
            )
        self.metadata_key_usage = metadata_key_usage
        raw_keypairs = conf.get("encryption_keypairs", [])
        if not isinstance(raw_keypairs, list):
            raise TypeError("encryption_keypairs must be a list")
        self.encryption_keypairs = []
        for pair in raw_keypairs:
            if not isinstance(pair, dict) or not pair.get("key_file"):
                raise ValueError("each encryption_keypairs entry requires key_file")
            self.encryption_keypairs.append(dict(pair))

        # Reset before (re)loading so a reused SPConfig instance does not
        # accumulate stale metadata across load() calls.
        self.metadata = MetadataStore()
        metadata_config = conf.get("metadata", {})
        unsupported = set(metadata_config) - {"local", "remote"}
        if unsupported:
            raise ValueError(
                "unsupported metadata source(s): " + ", ".join(sorted(unsupported))
            )
        for path in metadata_config.get("local", []):
            self._load_metadata_file(path)
        for source in metadata_config.get("remote", []):
            self._load_remote_metadata(source)

        return self

    def _load_metadata_file(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as fh:
                xml = fh.read()
        except OSError as exc:
            raise SourceNotFound(
                f"could not read metadata source {path!r}: {exc}"
            ) from exc
        document = _md.parse_document(xml)
        entity_list = [item.entity for item in document.entities]
        self._validate_metadata_document(document, require_expiry=False)
        self.metadata.add_source(path, entity_list)

    def _load_remote_metadata(self, source: Any) -> None:
        if (
            not isinstance(source, dict)
            or not source.get("url")
            or not source.get("cert")
        ):
            raise ValueError("remote metadata entries require url and cert")
        url = str(source["url"])
        if urllib.parse.urlsplit(url).scheme.lower() != "https":
            raise SourceNotFound("remote metadata URL must use HTTPS")
        cert_path = str(source["cert"])
        try:
            with open(cert_path, "rb") as fh:
                cert = fh.read()
        except OSError as exc:
            raise SourceNotFound(
                f"could not read metadata signing certificate {cert_path!r}: {exc}"
            ) from exc
        try:
            request = urllib.request.Request(
                url,
                headers={"Accept": "application/samlmetadata+xml, application/xml"},
            )
            opener = urllib.request.build_opener(_HttpsOnlyRedirectHandler())
            with opener.open(request, timeout=10) as response:
                if urllib.parse.urlsplit(response.geturl()).scheme.lower() != "https":
                    raise SourceNotFound("remote metadata redirected away from HTTPS")
                length = response.headers.get("Content-Length")
                if length is not None and int(length) > _MAX_REMOTE_METADATA_BYTES:
                    raise SourceNotFound("remote metadata exceeds the 32 MiB limit")
                body = response.read(_MAX_REMOTE_METADATA_BYTES + 1)
        except SourceNotFound:
            raise
        except (OSError, urllib.error.URLError, ValueError) as exc:
            raise SourceNotFound(
                f"could not fetch metadata source {url!r}: {exc}"
            ) from exc
        if len(body) > _MAX_REMOTE_METADATA_BYTES:
            raise SourceNotFound("remote metadata exceeds the 32 MiB limit")
        try:
            xml = body.decode("utf-8")
            document = _md.parse_document(xml)
            results = SamlVerifier.from_cert(cert).verify_all_enveloped(xml)
        except Exception as exc:
            raise SourceNotFound(
                f"remote metadata verification failed for {url!r}: {exc}"
            ) from exc
        root_id = document.root_id or ""
        root_is_verified = any(
            result.is_valid() and root_id in set(result.signed_reference_ids())
            for result in results
        )
        if not root_is_verified:
            raise SourceNotFound(
                f"remote metadata has no valid signature covering the document root for {url!r}"
            )
        entity_list = [item.entity for item in document.entities]
        self._validate_metadata_document(document, require_expiry=True)
        self.metadata.add_source(url, entity_list)

    def _validate_metadata_document(
        self, document: _md.MetadataDocument, *, require_expiry: bool
    ) -> None:
        now = datetime.now(timezone.utc)
        for item in document.entities:
            entity = item.entity
            _md.validate_entity(entity)
            expiry = item.effective_valid_until
            if require_expiry and expiry is None:
                raise ValueError(
                    f"remote metadata entity {entity.entity_id!r} has no finite validUntil"
                )
            if expiry is not None and expiry <= now:
                raise ValueError(f"metadata entity {entity.entity_id!r} has expired")
            if entity.is_idp():
                if not entity.single_sign_on_services():
                    raise ValueError(
                        f"IdP metadata {entity.entity_id!r} has no SSO endpoint"
                    )
                signatures_required = (
                    self.want_response_signed
                    or self.want_assertions_signed
                    or self.want_logout_response_signed
                )
                if (
                    signatures_required
                    and (require_expiry or self._signature_policy_explicit)
                    and not entity.signing_certificates("idp")
                ):
                    raise ValueError(
                        f"IdP metadata {entity.entity_id!r} has no signing certificate"
                    )

    def getattr(self, attribute: str, context: str | None = None) -> Any:
        """Read a setting using pysaml2's optional service context."""
        if context == "sp":
            return self._sp.get(attribute)
        return self.raw.get(attribute, getattr(self, attribute, None))

    def endpoint(
        self, service: str, binding: str | None = None, context: str = "sp"
    ) -> list[str]:
        """Return configured endpoint URLs for a service and optional binding."""
        if context != "sp":
            return []
        endpoints = {
            "assertion_consumer_service": self.acs_endpoints,
            "single_logout_service": self.slo_endpoints,
        }.get(service, [])
        return [
            url
            for url, item_binding in endpoints
            if binding is None or item_binding == binding
        ]

    # -- accessors used by the client / metadata shims --------------------

    def acs(self, binding: str | None = None) -> tuple[str, str]:
        """Return the (url, binding) ACS endpoint, preferring ``binding``."""
        if binding is not None:
            for url, b in self.acs_endpoints:
                if b == binding:
                    return url, b
        if not self.acs_endpoints:
            raise ValueError("no assertion_consumer_service endpoint configured")
        return self.acs_endpoints[0]

    def slo(self, binding: str | None = None) -> tuple[str, str] | None:
        """Return the SP logout endpoint, preferring ``binding`` when present."""
        if binding is not None:
            for url, b in self.slo_endpoints:
                if b == binding:
                    return url, b
        return self.slo_endpoints[0] if self.slo_endpoints else None

    def only_idp(self) -> str | None:
        """The single IdP this SP federates with, if unambiguous.

        Explicitly configured IdPs take precedence: more than one configured IdP
        is genuinely ambiguous and must NOT be resolved from metadata (which could
        otherwise hide the ambiguity). Metadata discovery is only a fallback when
        no IdPs are configured at all.
        """
        if self.idp:
            return next(iter(self.idp)) if len(self.idp) == 1 else None
        idp_md = [eid for eid, ed in self.metadata.items() if ed.is_idp()]
        if len(idp_md) == 1:
            return idp_md[0]
        return None

    def single_sign_on_service(
        self, idp_entity_id: str | None, binding: str = BINDING_HTTP_REDIRECT
    ) -> str:
        """Resolve an IdP SSO endpoint from explicit config or metadata."""
        idp_entity_id = idp_entity_id or self.only_idp()
        cfg = self.idp.get(idp_entity_id or "", {}).get("single_sign_on_service", {})
        if binding in cfg:
            return cfg[binding]
        ed = self.metadata.get(idp_entity_id or "")
        if ed is not None:
            for ep in ed.single_sign_on_services():
                if ep.binding == binding:
                    return ep.location
        raise ValueError(
            f"no SingleSignOnService for {idp_entity_id!r} with binding {binding}"
        )

    def single_logout_service(
        self, idp_entity_id: str | None, binding: str = BINDING_HTTP_REDIRECT
    ) -> str:
        """Resolve an IdP logout endpoint from explicit config or metadata."""
        idp_entity_id = idp_entity_id or self.only_idp()
        cfg = self.idp.get(idp_entity_id or "", {}).get("single_logout_service", {})
        if binding in cfg:
            return cfg[binding]
        ed = self.metadata.get(idp_entity_id or "")
        if ed is not None:
            for ep in ed.single_logout_services("idp"):
                if ep.binding == binding:
                    return ep.location
        raise ValueError(
            f"no SingleLogoutService for {idp_entity_id!r} with binding {binding}"
        )

    def single_logout_response_service(
        self, idp_entity_id: str | None, binding: str = BINDING_HTTP_REDIRECT
    ) -> str:
        """Resolve a LogoutResponse target, preferring metadata ResponseLocation."""
        idp_entity_id = idp_entity_id or self.only_idp()
        ed = self.metadata.get(idp_entity_id or "")
        if ed is not None:
            for endpoint in ed.single_logout_services("idp"):
                if endpoint.binding == binding and endpoint.response_location:
                    return endpoint.response_location
        return self.single_logout_service(idp_entity_id, binding)

    def idp_signing_certs(self, idp_entity_id: str | None) -> list[bytes]:
        """All IdP signing certificates (DER) from parsed metadata.

        During key rollover an IdP commonly publishes the old and new signing
        certificates simultaneously, so callers must be prepared to verify a
        signature against any of them - never just the first.
        """
        idp_entity_id = idp_entity_id or self.only_idp()
        ed = self.metadata.get(idp_entity_id or "")
        if ed is None:
            raise ValueError(f"no metadata for IdP {idp_entity_id!r}")
        certs = ed.signing_certificates("idp")
        if not certs:
            raise ValueError(
                f"IdP {idp_entity_id!r} metadata has no signing certificate"
            )
        return list(certs)

    def idp_signing_cert(self, idp_entity_id: str | None) -> bytes:
        """First IdP signing certificate (DER) from parsed metadata.

        Prefer :meth:`idp_signing_certs` for signature verification: verifying
        against only the first certificate breaks during key rollover.
        """
        return self.idp_signing_certs(idp_entity_id)[0]


# Acceptable alias: pysaml2 also exposes a generic Config.
Config = SPConfig
