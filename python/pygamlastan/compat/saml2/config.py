"""``saml2.config`` shim: :class:`SPConfig` reads the existing eduID
``saml2_settings.py`` dict and exposes just what the client/metadata shims need.

Only the keys eduID actually sets are interpreted; unknown keys (``xmlsec_binary``,
``attribute_map_dir``, ``contact_person``, ``organization``, ``debug`` ...) are
accepted and ignored, since pygamlastan needs none of them.
"""

from __future__ import annotations

from typing import Any

from pygamlastan import metadata as _md
from pygamlastan.core import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT


class SPConfig:
    """A minimal SP configuration parsed from an eduID-style settings dict."""

    def __init__(self) -> None:
        self.entityid: str | None = None
        self.name: str | None = None
        # endpoints: list of (url, binding)
        self.acs_endpoints: list[tuple[str, str]] = []
        self.slo_endpoints: list[tuple[str, str]] = []
        # idp config: {entity_id: {"single_sign_on_service": {binding: url},
        #                          "single_logout_service": {binding: url}}}
        self.idp: dict[str, dict[str, dict[str, str]]] = {}
        self.want_response_signed: bool = True
        self.key_file: str | None = None
        self.cert_file: str | None = None
        # parsed metadata EntityDescriptors keyed by entity id
        self.metadata: dict[str, _md.EntityDescriptor] = {}

    # -- loading ----------------------------------------------------------

    def load(self, conf: dict[str, Any]) -> SPConfig:
        self.entityid = conf.get("entityid")
        sp = conf.get("service", {}).get("sp", {})
        self.name = sp.get("name")

        endpoints = sp.get("endpoints", {})
        self.acs_endpoints = [tuple(e) for e in endpoints.get("assertion_consumer_service", [])]
        self.slo_endpoints = [tuple(e) for e in endpoints.get("single_logout_service", [])]

        self.idp = dict(sp.get("idp", {}))
        # pysaml2 defaults want_response_signed to True.
        self.want_response_signed = bool(sp.get("want_response_signed", True))

        self.key_file = conf.get("key_file")
        self.cert_file = conf.get("cert_file")

        # Reset before (re)loading so a reused SPConfig instance does not
        # accumulate stale metadata across load() calls.
        self.metadata = {}
        for path in conf.get("metadata", {}).get("local", []):
            self._load_metadata_file(path)

        return self

    def _load_metadata_file(self, path: str) -> None:
        with open(path, encoding="utf-8") as fh:
            xml = fh.read()
        try:
            entities = _md.parse_entities(xml)
        except Exception:
            entities = [_md.parse_entity(xml)]
        for ed in entities:
            self.metadata[ed.entity_id] = ed

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
        idp_entity_id = idp_entity_id or self.only_idp()
        cfg = self.idp.get(idp_entity_id or "", {}).get("single_sign_on_service", {})
        if binding in cfg:
            return cfg[binding]
        ed = self.metadata.get(idp_entity_id or "")
        if ed is not None:
            for ep in ed.single_sign_on_services():
                if ep.binding == binding:
                    return ep.location
        raise ValueError(f"no SingleSignOnService for {idp_entity_id!r} with binding {binding}")

    def single_logout_service(
        self, idp_entity_id: str | None, binding: str = BINDING_HTTP_REDIRECT
    ) -> str:
        idp_entity_id = idp_entity_id or self.only_idp()
        cfg = self.idp.get(idp_entity_id or "", {}).get("single_logout_service", {})
        if binding in cfg:
            return cfg[binding]
        ed = self.metadata.get(idp_entity_id or "")
        if ed is not None:
            for ep in ed.single_logout_services("idp"):
                if ep.binding == binding:
                    return ep.location
        raise ValueError(f"no SingleLogoutService for {idp_entity_id!r} with binding {binding}")

    def idp_signing_cert(self, idp_entity_id: str | None) -> bytes:
        """First IdP signing certificate (DER) from parsed metadata."""
        idp_entity_id = idp_entity_id or self.only_idp()
        ed = self.metadata.get(idp_entity_id or "")
        if ed is None:
            raise ValueError(f"no metadata for IdP {idp_entity_id!r}")
        certs = ed.signing_certificates("idp")
        if not certs:
            raise ValueError(f"IdP {idp_entity_id!r} metadata has no signing certificate")
        return certs[0]


# Acceptable alias: pysaml2 also exposes a generic Config.
Config = SPConfig
