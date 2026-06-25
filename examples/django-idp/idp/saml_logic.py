"""All pygamlastan interaction for the IdP, kept out of the views.

Inbound  : decode an AuthnRequest (Redirect or POST), parse it, process it
           against the SP's metadata.
Outbound : build an assertion for the authenticated user, sign it (enveloped
           XML-DSig over the assertion - SPs commonly require WantAssertionsSigned),
           and wrap it in an auto-submitting HTTP-POST form aimed at the SP's ACS.
"""
from __future__ import annotations

from pygamlastan import bindings, core, crypto, metadata, profiles, xml
from pygamlastan import idp as gidp

from .idp_config import IdpConfig

_SAML_MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"


# --- IdP metadata ----------------------------------------------------------

def idp_metadata_xml(cfg: IdpConfig) -> str:
    """The IdP's own SAML metadata, advertising both SSO bindings and the
    signing certificate. Hand this URL to the SPs you federate with."""
    return (
        f'<md:EntityDescriptor xmlns:md="{_SAML_MD_NS}" entityID="{cfg.entity_id}">'
        # errorURL is required by SWAMID Tech 5.1.13.
        '<md:IDPSSODescriptor WantAuthnRequestsSigned="false" '
        f'errorURL="{cfg.error_url}" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<md:KeyDescriptor use="signing">'
        f'<ds:KeyInfo xmlns:ds="{_DS_NS}"><ds:X509Data>'
        f"<ds:X509Certificate>{cfg.cert_b64}</ds:X509Certificate>"
        "</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
        f"<md:NameIDFormat>{core.NAMEID_TRANSIENT}</md:NameIDFormat>"
        f"<md:NameIDFormat>{core.NAMEID_PERSISTENT}</md:NameIDFormat>"
        f"<md:NameIDFormat>{core.NAMEID_EMAIL}</md:NameIDFormat>"
        f'<md:SingleSignOnService Binding="{core.BINDING_HTTP_REDIRECT}" Location="{cfg.sso_url}"/>'
        f'<md:SingleSignOnService Binding="{core.BINDING_HTTP_POST}" Location="{cfg.sso_url}"/>'
        "</md:IDPSSODescriptor></md:EntityDescriptor>"
    )


# --- Inbound ---------------------------------------------------------------

def _duplicate_preserving_form_pairs(form) -> list[tuple[str, str]]:
    if hasattr(form, "lists"):
        return [(name, value) for name, values in form.lists() for value in values]
    if hasattr(form, "items"):
        return list(form.items())
    return list(form)


def decode_authn_request(method: str, query_string: str, form) -> tuple[str, str | None]:
    """Return (saml_xml_text, relay_state) from a Redirect (GET) or POST request."""
    if method == "POST":
        decoded = bindings.post_decode(_duplicate_preserving_form_pairs(form))
    else:
        # The raw, still-percent-encoded query string (do NOT pre-decode it).
        decoded = bindings.redirect_decode(query_string)
    return decoded.saml_text, decoded.relay_state


def parse_authn(saml_text: str):
    return xml.parse_authn_request(saml_text)


def process_authn(authn, sp_metadata_xml: str):
    """Validate the request against the SP metadata and resolve the ACS to use."""
    entity = metadata.parse_entity(sp_metadata_xml)
    return profiles.process_authn_request(authn, sp_metadata=entity)


# --- Outbound --------------------------------------------------------------

def _signature_template(elem_id: str, cert_b64: str) -> str:
    return (
        f'<ds:Signature xmlns:ds="{_DS_NS}"><ds:SignedInfo>'
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        f'<ds:Reference URI="#{elem_id}"><ds:Transforms>'
        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms>'
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        "<ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/>"
        f"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate>"
        "</ds:X509Data></ds:KeyInfo></ds:Signature>"
    )


def _sign_assertion(response_xml: str, assertion_id: str, cfg: IdpConfig) -> str:
    """Splice an enveloped <ds:Signature> into the assertion and fill it in.

    gamlastan signs a template: we insert the <ds:Signature> right after the
    assertion's <saml:Issuer> (the schema position), pointing its Reference at the
    assertion id, then the signer computes the digest and signature.
    """
    template = _signature_template(assertion_id, cfg.cert_b64)
    a_pos = response_xml.index("<saml:Assertion")
    issuer_close = response_xml.index("</saml:Issuer>", a_pos) + len("</saml:Issuer>")
    spliced = response_xml[:issuer_close] + template + response_xml[issuer_close:]
    signer = crypto.SamlSigner.from_pem(cfg.key_pem)
    return signer.sign_enveloped(spliced)


def _user_attributes(user, cfg: IdpConfig) -> list:
    """A standard eduPerson attribute set derived from the Django user (URI names).

    Scoped attributes (eduPersonPrincipalName, eduPersonScopedAffiliation) use the
    home-org scope from ``cfg.scope`` (SAML_IDP_SCOPE) and are only emitted when a
    scope is configured.
    """
    fmt = core.ATTRNAME_FORMAT_URI
    full_name = user.get_full_name() or user.get_username()
    attrs = [
        core.Attribute(
            "urn:oid:2.16.840.1.113730.3.1.241", values=[full_name],
            friendly_name="displayName", name_format=fmt,
        ),
        core.Attribute(
            "urn:oid:0.9.2342.19200300.100.1.1", values=[user.get_username()],
            friendly_name="uid", name_format=fmt,
        ),
    ]
    if user.first_name:
        attrs.append(
            core.Attribute(
                "urn:oid:2.5.4.42", values=[user.first_name],
                friendly_name="givenName", name_format=fmt,
            )
        )
    if user.last_name:
        attrs.append(
            core.Attribute(
                "urn:oid:2.5.4.4", values=[user.last_name],
                friendly_name="sn", name_format=fmt,
            )
        )
    if user.email:
        attrs.append(
            core.Attribute(
                "urn:oid:0.9.2342.19200300.100.1.3", values=[user.email],
                friendly_name="mail", name_format=fmt,
            )
        )
    if cfg.scope:
        attrs.append(
            core.Attribute(
                "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
                values=[f"{user.get_username()}@{cfg.scope}"],
                friendly_name="eduPersonPrincipalName", name_format=fmt,
            )
        )
        attrs.append(
            core.Attribute(
                "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
                values=[f"member@{cfg.scope}"],
                friendly_name="eduPersonScopedAffiliation", name_format=fmt,
            )
        )
    return attrs


def _make_nameid(name_id_format: str | None, user, cfg: IdpConfig, sp_entity_id: str):
    """Honour the SP's requested NameID format; default to transient."""
    fmt = name_id_format
    if fmt and fmt.endswith("emailAddress"):
        value = user.email or user.get_username()
    elif fmt and fmt.endswith("persistent"):
        # Stable, opaque, per-SP identifier (eduPersonTargetedID style).
        value = gidp.Eptid(cfg.nameid_secret).get(cfg.entity_id, sp_entity_id, str(user.pk))
    else:
        fmt = core.NAMEID_TRANSIENT
        value = core.generate_id()
    return core.NameId(
        value, format=fmt, name_qualifier=cfg.entity_id, sp_name_qualifier=sp_entity_id
    )


def build_signed_response(
    *, sp_entity_id: str, acs_url: str, request_id: str | None,
    name_id_format: str | None, user, cfg: IdpConfig,
) -> str:
    """Build and assertion-sign a SAML Response for `user`; return the XML."""
    nameid = _make_nameid(name_id_format, user, cfg, sp_entity_id)
    options = profiles.ResponseOptions(
        cfg.entity_id, sp_entity_id, acs_url,
        assertion_lifetime_seconds=300,
        in_response_to=request_id,
        session_index=core.generate_id(),
        authn_context_class_ref=core.AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT,
        attributes=_user_attributes(user, cfg),
    )
    response = profiles.create_response(options, nameid)
    return _sign_assertion(response.to_xml(), response.assertions[0].id, cfg)


def encode_post_response(signed_xml: str, acs_url: str, relay_state: str | None) -> str:
    """A complete self-submitting HTML page that POSTs the response to the SP."""
    return bindings.post_encode(signed_xml.encode(), False, acs_url, relay_state=relay_state)
