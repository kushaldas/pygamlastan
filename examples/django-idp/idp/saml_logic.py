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


def decode_authn_request(method: str, query_string: str, form):
    """Return the decoded binding message from a Redirect (GET) or POST request.

    The returned object carries the SAML text and relay state, and, for the
    Redirect binding, the detached signature (``sig_alg`` / ``signature`` /
    ``signature_input``) needed to authenticate the request.
    """
    if method == "POST":
        return bindings.post_decode(_duplicate_preserving_form_pairs(form))
    # The raw, still-percent-encoded query string (do NOT pre-decode it).
    return bindings.redirect_decode(query_string)


def parse_authn(saml_text: str):
    return xml.parse_authn_request(saml_text)


def _sp_verifiers(entity) -> list:
    """One verifier per SP metadata signing certificate (empty if the SP
    publishes no signing key). During key rollover metadata publishes the old
    and new certificates simultaneously, and a request signed by any published
    certificate is trusted - so never verify against just the first one."""
    return [
        crypto.SamlVerifier.from_cert(cert_der)
        for cert_der in entity.signing_certificates("sp")
    ]


def _verify_authn_request_signature(authn, saml_text, decoded, entity) -> bool:
    """Cryptographically verify every signature representation present on the
    AuthnRequest against the SP's metadata keys.

    Returns True when at least one representation is present and every present
    representation verifies against one of the SP's published certificates.
    Raises ValueError on an invalid signature so a forgery can never be
    downgraded to "unsigned". Returns False when the request carries no
    signature at all, letting ``process_authn_request`` enforce the SP's
    ``AuthnRequestsSigned`` policy and fail closed when signing is required.
    """
    verifiers = _sp_verifiers(entity)
    verified = False

    # HTTP-Redirect binding: detached signature over the exact query string.
    sig_alg = getattr(decoded, "sig_alg", None)
    signature = getattr(decoded, "signature", None)
    signature_input = getattr(decoded, "signature_input", None)
    # An incomplete tuple must never downgrade to "unsigned": the decoder
    # permits SigAlg without Signature, so stripping just the Signature
    # parameter would otherwise reach process_authn_request as an unsigned
    # request and be accepted whenever the SP does not require signing.
    if any((sig_alg, signature, signature_input)) and not (
        sig_alg and signature and signature_input
    ):
        raise ValueError(
            "AuthnRequest redirect signature is incomplete: SigAlg, Signature "
            "and the signed query must all be present"
        )
    if sig_alg and signature and signature_input:
        if not verifiers:
            raise ValueError("AuthnRequest is signed but the SP publishes no signing key")
        # verify_redirect_query can RAISE for a particular certificate (e.g. a
        # key-type/algorithm mismatch on a retired rollover key) instead of
        # returning False, so a plain any() would abort at the first such
        # certificate. Try every published certificate; fail only after all
        # were attempted.
        input_bytes = signature_input.encode("utf-8")
        redirect_ok = False
        redirect_error: Exception | None = None
        for verifier in verifiers:
            try:
                if verifier.verify_redirect_query(input_bytes, signature, sig_alg):
                    redirect_ok = True
                    break
            except Exception as e:
                redirect_error = e
        if not redirect_ok:
            raise ValueError(
                "AuthnRequest redirect signature is invalid"
            ) from redirect_error
        verified = True

    # Enveloped XML-DSig, bound to the request element so a wrapped signature
    # over a sibling object cannot authenticate this request.
    if authn.has_signature:
        if not verifiers:
            raise ValueError("AuthnRequest is signed but the SP publishes no signing key")
        last_error: Exception | None = None
        for verifier in verifiers:
            try:
                signed_ids = [
                    ref
                    for result in verifier.verify_all_enveloped(saml_text)
                    for ref in result.signed_reference_ids()
                ]
            except Exception as e:
                # Not signed by this (rollover) certificate; try the next.
                last_error = e
                continue
            if authn.id in signed_ids:
                break
            last_error = ValueError(
                "AuthnRequest signature does not cover the request element"
            )
        else:
            raise ValueError(
                "AuthnRequest signature did not verify against any published "
                f"SP signing certificate: {last_error}"
            ) from last_error
        verified = True

    return verified


def process_authn(authn, saml_text: str, decoded, sp_metadata_xml: str):
    """Verify the request signature against the SP metadata, then resolve the ACS.

    Passing verified provenance (not signature markup) into
    ``process_authn_request`` is what lets it enforce the SP's
    ``AuthnRequestsSigned`` policy safely.
    """
    entity = metadata.parse_entity(sp_metadata_xml)
    signature_verified = _verify_authn_request_signature(authn, saml_text, decoded, entity)
    return profiles.process_authn_request(
        authn, entity, request_signature_verified=signature_verified
    )


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
    authn_instant=None,
) -> str:
    """Build and assertion-sign a SAML Response for `user`; return the XML.

    ``authn_instant`` is *when the principal actually authenticated* to the IdP.
    When an existing browser session is reused (the user was already logged in
    when the AuthnRequest arrived) this predates the response issue time, so it
    must be reported separately - otherwise the IdP over-reports authentication
    freshness to SPs that enforce it (``ForceAuthn`` / ``RequestedAuthnContext``
    / a max-age policy). Pass the real login time (e.g. Django's
    ``user.last_login``); when ``None`` the library treats it as a fresh login
    and uses the issue instant.
    """
    nameid = _make_nameid(name_id_format, user, cfg, sp_entity_id)
    options = profiles.ResponseOptions(
        cfg.entity_id, sp_entity_id, acs_url,
        assertion_lifetime_seconds=300,
        in_response_to=request_id,
        session_index=core.generate_id(),
        authn_context_class_ref=core.AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT,
        attributes=_user_attributes(user, cfg),
    )
    response = profiles.create_response(options, nameid, authn_instant=authn_instant)
    return _sign_assertion(response.to_xml(), response.assertions[0].id, cfg)


def encode_post_response(signed_xml: str, acs_url: str, relay_state: str | None) -> str:
    """A complete self-submitting HTML page that POSTs the response to the SP."""
    return bindings.post_encode(signed_xml.encode(), False, acs_url, relay_state=relay_state)
