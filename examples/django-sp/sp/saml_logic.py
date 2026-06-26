"""All pygamlastan interaction for the SP, kept out of the views.

Outbound : build an ``AuthnRequest`` and encode it for the HTTP-Redirect binding.
Inbound  : decode the ``Response`` posted to the ACS, verify its signature and
           validate it with the safe ``process_response_verified`` entry point,
           and hand back the released identity/attributes.
Metadata : publish SPSSODescriptor metadata (with mdui, contacts, requested
           attributes and the REFEDS R&S entity category) for federation.
"""
from __future__ import annotations

import urllib.parse
from xml.sax.saxutils import escape, quoteattr

from pygamlastan import bindings, core, crypto, profiles, security, xml

from .sp_config import SpConfig

_MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_MDUI_NS = "urn:oasis:names:tc:SAML:metadata:ui"
_MDATTR_NS = "urn:oasis:names:tc:SAML:metadata:attribute"
_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_REMD_NS = "http://refeds.org/metadata"
_IDPDISC_NS = "urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol"
_FMT = core.ATTRNAME_FORMAT_URI

# The attributes this SP asks IdPs to release (eduPerson essentials). Each is a
# (FriendlyName, Name, isRequired) triple.
REQUESTED_ATTRIBUTES = [
    ("displayName", "urn:oid:2.16.840.1.113730.3.1.241", False),
    ("givenName", "urn:oid:2.5.4.42", False),
    ("sn", "urn:oid:2.5.4.4", False),
    ("mail", "urn:oid:0.9.2342.19200300.100.1.3", False),
    ("eduPersonPrincipalName", "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", True),
    ("eduPersonScopedAffiliation", "urn:oid:1.3.6.1.4.1.5923.1.1.1.9", False),
]

# Process-wide replay cache for the assertion IDs we accept.
_replay_cache = security.InMemoryReplayCache()


class _InMemoryPersistentIdStore:
    """A minimal PersistentIdStoreProtocol implementation (demo, single process).

    process_response_verified requires a store whenever the assertion carries a
    persistent NameID: it binds (NameID, SP) to a principal and flags a *different*
    principal later presenting the same persistent NameID (a reassignment attack).
    Returns True if the binding is new or unchanged, False on conflict. It fails
    closed: any error here is treated by the binding as a conflict. In-memory only
    (not shared across gunicorn workers); back it with a database for real use.
    """

    def __init__(self):
        self._seen: dict[tuple[str, str], str] = {}

    def check_and_record(self, name_id: str, sp_entity_id: str, principal: str) -> bool:
        key = (name_id, sp_entity_id)
        existing = self._seen.get(key)
        if existing is None:
            self._seen[key] = principal
            return True
        return existing == principal


_persistent_id_store = _InMemoryPersistentIdStore()


# --- SP metadata -----------------------------------------------------------

def _contact(cfg: SpConfig, contact_type: str, email: str, extra: str = "") -> str:
    if not email:
        return ""
    return (
        f'<md:ContactPerson contactType={quoteattr(contact_type)}{extra}>'
        f"<md:EmailAddress>mailto:{escape(email)}</md:EmailAddress>"
        "</md:ContactPerson>"
    )


def sp_metadata_xml(cfg: SpConfig) -> str:
    """The SP's SAML metadata: an SPSSODescriptor with the ACS, signing and
    encryption keys, requested attributes, UI info, organization and contacts,
    plus the REFEDS Research & Scholarship entity category (drives attribute
    release at R&S-supporting IdPs). Hand this to the federation to register."""
    key_info = (
        f'<ds:KeyInfo xmlns:ds="{_DS_NS}"><ds:X509Data>'
        f"<ds:X509Certificate>{cfg.cert_b64}</ds:X509Certificate>"
        "</ds:X509Data></ds:KeyInfo>"
    )
    requested = "".join(
        f'<md:RequestedAttribute FriendlyName={quoteattr(fn)} Name={quoteattr(name)} '
        f'NameFormat={quoteattr(_FMT)} isRequired="{str(req).lower()}"/>'
        for fn, name, req in REQUESTED_ATTRIBUTES
    )
    security_contact = _contact(
        cfg, "other", cfg.security_email,
        extra=f' xmlns:remd="{_REMD_NS}" '
        'remd:contactType="http://refeds.org/metadata/contactType/security"',
    )
    return (
        f'<md:EntityDescriptor xmlns:md="{_MD_NS}" entityID={quoteattr(cfg.entity_id)}>'
        # REFEDS R&S entity category (entity-level attribute).
        "<md:Extensions>"
        f'<mdattr:EntityAttributes xmlns:mdattr="{_MDATTR_NS}">'
        f'<saml:Attribute xmlns:saml="{_SAML_NS}" Name="http://macedir.org/entity-category" '
        f'NameFormat={quoteattr(_FMT)}>'
        "<saml:AttributeValue>https://refeds.org/category/research-and-scholarship</saml:AttributeValue>"
        "</saml:Attribute></mdattr:EntityAttributes>"
        "</md:Extensions>"
        '<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        # UI info (mdui): display name + description shown by IdP discovery.
        "<md:Extensions>"
        f'<mdui:UIInfo xmlns:mdui="{_MDUI_NS}">'
        f'<mdui:DisplayName xml:lang="en">{escape(cfg.display_name)}</mdui:DisplayName>'
        f'<mdui:Description xml:lang="en">{escape(cfg.description)}</mdui:Description>'
        f'<mdui:InformationURL xml:lang="en">{escape(cfg.info_url)}</mdui:InformationURL>'
        f'<mdui:PrivacyStatementURL xml:lang="en">{escape(cfg.privacy_url)}</mdui:PrivacyStatementURL>'
        "</mdui:UIInfo>"
        # DiscoveryResponse: the endpoint the discovery service returns to. The
        # SeamlessAccess DS validates the SAMLDS `return` URL against this, so it
        # must match cfg.disco_return_url exactly.
        f'<idpdisc:DiscoveryResponse xmlns:idpdisc="{_IDPDISC_NS}" '
        f'Binding="{_IDPDISC_NS}" Location={quoteattr(cfg.disco_return_url)} index="0"/>'
        "</md:Extensions>"
        f'<md:KeyDescriptor use="signing">{key_info}</md:KeyDescriptor>'
        f'<md:KeyDescriptor use="encryption">{key_info}</md:KeyDescriptor>'
        f"<md:NameIDFormat>{core.NAMEID_PERSISTENT}</md:NameIDFormat>"
        f"<md:NameIDFormat>{core.NAMEID_TRANSIENT}</md:NameIDFormat>"
        f'<md:AssertionConsumerService Binding="{core.BINDING_HTTP_POST}" '
        f'Location={quoteattr(cfg.acs_url)} index="0" isDefault="true"/>'
        '<md:AttributeConsumingService index="0">'
        f'<md:ServiceName xml:lang="en">{escape(cfg.display_name)}</md:ServiceName>'
        f'<md:ServiceDescription xml:lang="en">{escape(cfg.description)}</md:ServiceDescription>'
        f"{requested}"
        "</md:AttributeConsumingService>"
        "</md:SPSSODescriptor>"
        "<md:Organization>"
        f'<md:OrganizationName xml:lang="en">{escape(cfg.org_name)}</md:OrganizationName>'
        f'<md:OrganizationDisplayName xml:lang="en">{escape(cfg.org_display_name)}</md:OrganizationDisplayName>'
        f'<md:OrganizationURL xml:lang="en">{escape(cfg.org_url)}</md:OrganizationURL>'
        "</md:Organization>"
        f"{_contact(cfg, 'technical', cfg.technical_email)}"
        f"{_contact(cfg, 'support', cfg.support_email)}"
        f"{security_contact}"
        "</md:EntityDescriptor>"
    )


# --- Discovery: send the user to the discovery service ---------------------

def discovery_redirect_url(cfg: SpConfig) -> str:
    """The SAML IdP Discovery Protocol request URL: send the user here to pick an
    IdP. The DS returns to ``cfg.disco_return_url`` with ``?entityID=<chosen>``."""
    query = urllib.parse.urlencode(
        {"entityID": cfg.entity_id, "return": cfg.disco_return_url}
    )
    sep = "&" if "?" in cfg.discovery_url else "?"
    return f"{cfg.discovery_url}{sep}{query}"


# --- Outbound: build + send the AuthnRequest -------------------------------

def build_authn_redirect(cfg: SpConfig, idp_sso_url: str, relay_state: str | None):
    """Build an AuthnRequest for ``idp_sso_url`` and return (redirect_url, request_id).

    Store ``request_id`` in the session; it is checked as ``expected_request_id``
    when the Response comes back, binding the response to this request.
    """
    options = profiles.AuthnRequestOptions(
        sp_entity_id=cfg.entity_id,
        acs_url=cfg.acs_url,
        destination=idp_sso_url,
        protocol_binding=core.BINDING_HTTP_POST,   # how the IdP should reply
        name_id_format=core.NAMEID_PERSISTENT,
        allow_create=True,
    )
    request = profiles.create_authn_request(options)
    redirect_url = bindings.redirect_encode(
        request.to_xml().encode(), True, idp_sso_url, relay_state=relay_state
    )
    return redirect_url, request.id


# --- Inbound: process the Response posted to the ACS -----------------------

def _duplicate_preserving_form_pairs(form) -> list[tuple[str, str]]:
    """Flatten a Django QueryDict (or dict) to (name, value) pairs, preserving
    duplicates. ``post_decode`` wants the raw pairs so it can reject a request
    that smuggles a second SAMLResponse past a collapsing ``dict``."""
    if hasattr(form, "lists"):
        return [(name, value) for name, values in form.lists() for value in values]
    if hasattr(form, "items"):
        return list(form.items())
    return list(form)


def issuer_from_post(form) -> str | None:
    """The Response's Issuer (the IdP entityID), read without trusting it yet.

    Used to pick which IdP's metadata to resolve when the session that recorded
    the chosen IdP is unavailable. The issuer is only trusted after its metadata
    resolves and the signature verifies in ``process_acs``.
    """
    try:
        decoded = bindings.post_decode(_duplicate_preserving_form_pairs(form))
        return xml.parse_response(decoded.saml_text).issuer.value
    except Exception:  # noqa: BLE001
        return None


def process_acs(cfg: SpConfig, form, idp, expected_request_id: str | None):
    """Decode + verify + validate the Response at the ACS; return (AuthnResult,
    relay_state).

    Uses ``process_response_verified``: it performs XML-DSig verification over the
    exact response bytes with the IdP's signing cert and feeds only the
    cryptographically verified IDs into validation - no "trust me, it was signed"
    shortcut. Raises on any decode/verify/validation failure.
    """
    from . import idp_resolver

    decoded = bindings.post_decode(_duplicate_preserving_form_pairs(form))
    signing_cert = idp_resolver.signing_cert_der(idp)
    if signing_cert is None:
        raise ValueError("the IdP metadata has no signing certificate")
    verifier = crypto.SamlVerifier.from_cert(signing_cert)
    result = profiles.process_response_verified(
        decoded.saml_text,
        verifier,
        security.SecurityConfig(),
        sp_entity_id=cfg.entity_id,
        acs_url=cfg.acs_url,
        expected_idp_entity_id=idp.entity_id,
        expected_request_id=expected_request_id,
        replay_cache=_replay_cache,
        persistent_id_store=_persistent_id_store,
    )
    return result, decoded.relay_state


def attributes_for_display(result) -> list[dict]:
    """Flatten AuthnResult.attributes into rows for the template."""
    rows = []
    for attr in result.attributes:
        rows.append(
            {
                "friendly_name": attr.friendly_name or "",
                "name": attr.name,
                "values": list(attr.values),
            }
        )
    return rows
