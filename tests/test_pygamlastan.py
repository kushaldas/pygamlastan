"""Test suite for pygamlastan - the PyO3 binding over gamlastan (SAML 2.0).

The suite is organised one section per bound submodule (core, xml, crypto,
bindings, metadata, attribute_map, security, profiles, idp) plus a top-level
package/exceptions section. Each test documents *what behaviour it pins down*
and, where the reasoning isn't obvious, *why*.

Coverage philosophy:
  * Parsing tests feed hand-written XML and assert the owned Python objects
    expose the right values (the "owned-only at the FFI boundary" contract).
  * Round-trip tests build → serialise → re-parse to prove the encode and decode
    paths agree (bindings, metadata, attribute_map, NameID coding).
  * The crypto tests exercise *real* cryptography: a file-based enveloped
    XML-DSig sign→verify, a tamper-rejection check, and - when SoftHSM2 is
    installed - a genuine PKCS#11 signing operation against a provisioned token.
  * The profiles section drives the full Web-Browser-SSO flow end to end
    (IdP builds a Response → SP validates and extracts identity) and the replay
    cache, including a pure-Python cache implementing the protocol.

Fixtures (`rsa_keypair`, `softhsm`) live in conftest.py; the PKCS#11 test
self-skips when SoftHSM2 tooling is absent.
"""

import base64
from datetime import datetime, timedelta, timezone

import pytest

import pygamlastan
from pygamlastan import (
    attribute_map,
    bindings,
    core,
    crypto,
    idp,
    logout,
    metadata,
    profiles,
    security,
    xml,
)

# Stable entity IDs / endpoint URLs reused across the SSO tests.
IDP = "https://idp.example.org"
SP = "https://sp.example.org/sp"
ACS = "https://sp.example.org/acs"
# A fixed "current time" so assertion validity windows are deterministic and the
# generated responses (lifetime = NOW + 300s) always validate at NOW.
NOW = datetime(2026, 6, 25, 10, 0, 0, tzinfo=timezone.utc)

# A minimal, hand-written Response. It is deliberately incomplete (no
# Conditions / Bearer SubjectConfirmation / AuthnStatement) so it is fine for
# *parsing/navigation* tests but is NOT used where validation runs - validation
# tests use `_built_response_xml()` which produces a complete, compliant Response.
SAMPLE_RESPONSE = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" '
    'IssueInstant="2026-06-24T10:00:00Z" Destination="https://sp.example.org/acs" '
    'InResponseTo="_req1"><saml:Issuer>https://idp.example.org</saml:Issuer>'
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
    '</samlp:Status><saml:Assertion ID="_a1" Version="2.0" IssueInstant="2026-06-24T10:00:00Z">'
    '<saml:Issuer>https://idp.example.org</saml:Issuer><saml:Subject>'
    '<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">alice</saml:NameID>'
    "</saml:Subject><saml:AttributeStatement>"
    '<saml:Attribute Name="mail"><saml:AttributeValue>alice@example.org</saml:AttributeValue>'
    "</saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"
)

# An IdP EntityDescriptor advertising two SSO endpoints (Redirect + POST) and a
# transient NameID format - enough to exercise endpoint and format accessors.
SAMPLE_IDP_METADATA = (
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
    'entityID="https://idp.example.org"><md:IDPSSODescriptor '
    'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
    'Location="https://idp.example.org/sso"/>'
    '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
    'Location="https://idp.example.org/sso/post"/>'
    "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"
    "</md:IDPSSODescriptor></md:EntityDescriptor>"
)

# An SP-issued AuthnRequest carrying an Issuer, ACS URL/binding and a
# NameIDPolicy - the inputs the IdP side (`process_authn_request`) reads back.
AUTHN_REQUEST = (
    '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" '
    'IssueInstant="2026-06-24T10:00:00Z" Destination="https://idp.example.org/sso" '
    'AssertionConsumerServiceURL="https://sp.example.org/acs" '
    'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
    "<saml:Issuer>https://sp.example.org/sp</saml:Issuer>"
    '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" '
    'AllowCreate="true"/></samlp:AuthnRequest>'
)

SAMPLE_SP_METADATA = (
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
    'entityID="https://sp.example.org/sp"><md:SPSSODescriptor '
    'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
    'Location="https://sp.example.org/acs" index="0" isDefault="true"/>'
    "</md:SPSSODescriptor></md:EntityDescriptor>"
)


def _built_response_xml(
    in_response_to="_req123",
    name_id_value="alice@example.org",
    name_id_format=core.NAMEID_TRANSIENT,
):
    """Return the XML of a complete, *validatable* SAML Response.

    Unlike the hand-written ``SAMPLE_RESPONSE`` this goes through the IdP profile
    (`create_response`), so it contains every element the 32-check validator
    requires - Conditions/AudienceRestriction, a bearer SubjectConfirmation with
    NotOnOrAfter, and an AuthnStatement. Used by the validation/replay tests.
    """
    nid = core.NameId(name_id_value, format=name_id_format)
    ro = profiles.ResponseOptions(
        IDP, SP, ACS, assertion_lifetime_seconds=300, in_response_to=in_response_to,
        authn_context_class_ref=core.AUTHN_CONTEXT_PASSWORD,
        attributes=[core.Attribute("mail", values=["alice@example.org"])],
    )
    return profiles.create_response(ro, nid, now=NOW).to_xml()


# --------------------------------------------------------------------------- #
# Package / errors
# --------------------------------------------------------------------------- #

def test_version_and_submodules():
    """The package exposes its version and all ten gamlastan submodules.

    Guards the mixed Rust+Python layout: the `_native` extension must register
    each area (core, xml, ...) as an attribute of the `pygamlastan` package.
    """
    assert pygamlastan.__version__ == "0.3.0"
    for name in ("core", "xml", "crypto", "bindings", "metadata", "security",
                 "profiles", "attribute_map", "idp", "logout"):
        assert hasattr(pygamlastan, name)


def test_exception_hierarchy():
    """Per-module errors all derive from the single base `SamlError`.

    Callers can therefore catch one base class, or a specific subtype, as the
    error model decision intends.
    """
    assert issubclass(pygamlastan.SamlCryptoError, pygamlastan.SamlError)
    assert issubclass(pygamlastan.SamlProfileError, pygamlastan.SamlError)
    assert issubclass(pygamlastan.SamlError, Exception)


# --------------------------------------------------------------------------- #
# core
# --------------------------------------------------------------------------- #

def test_core_constants():
    """The SAML 2.0 constants re-exported from gamlastan have their spec values."""
    assert core.BINDING_HTTP_POST.endswith("HTTP-POST")
    assert core.NAMEID_TRANSIENT.endswith("transient")
    assert core.STATUS_SUCCESS.endswith("Success")
    assert core.SAML_ASSERTION_NS == "urn:oasis:names:tc:SAML:2.0:assertion"


def test_core_construct_nameid_issuer_attribute():
    """Build-side core types accept keyword args and round-trip their getters.

    These are the types callers construct to feed the IdP profile (NameID,
    Attribute) - so their constructors and accessors must agree.
    """
    nid = core.NameId("alice", format=core.NAMEID_TRANSIENT, sp_name_qualifier=SP)
    assert nid.value == "alice"
    assert nid.format == core.NAMEID_TRANSIENT
    assert nid.sp_name_qualifier == SP

    iss = core.Issuer(IDP)
    assert iss.value == IDP

    # Attribute values are given as plain strings; `string_values` reads them
    # back (it filters to string-typed AttributeValues, the common SATOSA case).
    attr = core.Attribute("mail", values=["a@x.org", "b@x.org"], name_format=core.ATTRNAME_FORMAT_URI)
    assert attr.name == "mail"
    assert attr.string_values == ["a@x.org", "b@x.org"]
    assert attr.name_format == core.ATTRNAME_FORMAT_URI


def test_generate_id_unique():
    """`generate_id()` yields fresh, XML-NCName-safe ids (leading underscore)."""
    a, b = core.generate_id(), core.generate_id()
    assert a != b and a.startswith("_")


def test_validate_entity_id():
    """Entity-id validation returns the value, and rejects the empty string."""
    assert core.validate_entity_id(IDP) == IDP
    with pytest.raises(pygamlastan.SamlCoreError):
        core.validate_entity_id("")


# --------------------------------------------------------------------------- #
# xml parsing
# --------------------------------------------------------------------------- #

def test_parse_response_navigation():
    """Parsing a Response yields owned objects navigable down to attributes.

    Walks Response → Status → Assertion → Subject/NameID → AttributeStatement,
    confirming the full nested-getter chain works and nothing borrows from the
    (now dropped) XML document.
    """
    r = xml.parse_response(SAMPLE_RESPONSE)
    assert r.id == "_resp1"
    assert r.is_success()
    assert r.in_response_to == "_req1"
    assert r.issuer.value == IDP
    a = r.assertions[0]
    assert a.id == "_a1"
    assert a.subject.name_id.value == "alice"
    attr = a.attribute_statements[0].attributes[0]
    assert attr.name == "mail"
    assert attr.string_values == ["alice@example.org"]


def test_parse_authn_request():
    """Parsing an AuthnRequest exposes Issuer, ACS URL and NameIDPolicy."""
    req = xml.parse_authn_request(AUTHN_REQUEST)
    assert req.id == "_req1"
    assert req.issuer.value == SP
    assert req.assertion_consumer_service_url == ACS
    assert req.name_id_policy.format == core.NAMEID_TRANSIENT
    assert req.name_id_policy.allow_create is True


def test_parse_invalid_xml_raises():
    """Non-SAML input surfaces as a typed `SamlXmlError`, not a panic/abort."""
    with pytest.raises(pygamlastan.SamlXmlError):
        xml.parse_response("<not-saml/>")


def test_parse_rejects_doctype_dtd():
    """`parse_secure` (used by every parse entry point) refuses any document
    carrying a DTD/DOCTYPE, closing the XXE / entity-smuggling vector. A
    legitimate SAML message never has a DTD, so this is always safe to reject."""
    xxe = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        ' ID="_x" Version="2.0" IssueInstant="2026-06-25T10:00:00Z">&xxe;</samlp:Response>'
    )
    with pytest.raises(pygamlastan.SamlXmlError):
        xml.parse_response(xxe)


def test_parse_rejects_billion_laughs():
    """uppsala 0.5's entity-expansion budget (inherited via `parse_secure`)
    bounds quadratic / billion-laughs amplification before validation runs. The
    document is rejected at the DTD guard regardless, but this asserts that a
    classic amplification payload never expands unbounded."""
    lol = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lolz ['
        '<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
        ']>'
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&lol3;</samlp:Response>'
    )
    with pytest.raises(pygamlastan.SamlXmlError):
        xml.parse_response(lol)


# --------------------------------------------------------------------------- #
# crypto
# --------------------------------------------------------------------------- #

def test_canonicalization():
    """C14N produces the expected byte stream for both modes.

    Exclusive C14N moves the namespace declaration onto the node that uses it;
    inclusive C14N keeps the document's original namespace placement. Both are
    prerequisites for correct XML-DSig digesting.
    """
    doc = '<a xmlns:b="urn:x"><b:c>hi</b:c></a>'
    assert crypto.exc_c14n(doc) == b'<a><b:c xmlns:b="urn:x">hi</b:c></a>'
    assert crypto.canonicalize(doc, "inclusive") == doc.encode()


def test_keysmanager_build(rsa_keypair):
    """The PEM convenience builders load at least one usable key.

    `build_sp` registers the SP signing key plus the trusted IdP cert;
    `build_idp` registers the IdP signing key.
    """
    priv, cert, _ = rsa_keypair
    km = crypto.KeysManager.build_sp(priv, cert)
    assert len(km) >= 1
    km2 = crypto.KeysManager.build_idp(priv)
    assert len(km2) >= 1


def _signature_template(elem_id, cert_b64):
    """Build an enveloped XML-DSig `<ds:Signature>` template.

    gamlastan signs a *template*: the caller supplies the SignedInfo, an empty
    DigestValue/SignatureValue, and the certificate in KeyInfo; the signer fills
    in the digest and signature. `elem_id` is the URI (#id) of the element being
    signed; `cert_b64` is the base64 DER of the signing certificate.
    """
    return (
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>'
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


def test_enveloped_sign_and_verify(rsa_keypair):
    """Real file-key enveloped XML-DSig: sign then verify succeeds.

    Signs a Response template with the private key, then verifies with a
    verifier trusting only the matching certificate. `signed_reference_ids()`
    must report the id of the element whose digest was actually checked - these
    are the IDs the SP profile treats as cryptographically signed. Time checks
    are skipped because the test cert/window are not time-aligned with NOW.
    """
    priv, cert, cert_b64 = rsa_keypair
    template = _signature_template("_resp1", cert_b64)
    unsigned = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'ID="_resp1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">'
        f"{template}<samlp:Status/></samlp:Response>"
    )
    signer = crypto.SamlSigner.from_pem(priv)
    signed = signer.sign_enveloped(unsigned)
    # The empty <ds:SignatureValue/> placeholder must now be filled.
    assert "<ds:SignatureValue>" in signed and "<ds:SignatureValue/>" not in signed

    verifier = crypto.SamlVerifier.from_cert(cert)
    verifier.set_skip_time_checks(True, unsafe_allow_skip_time_checks=True)
    result = verifier.verify_enveloped(signed)
    assert result.is_valid()
    assert bool(result) is True  # VerifyResult is truthy when valid
    assert "_resp1" in result.signed_reference_ids()


def test_verify_rejects_tampered(rsa_keypair):
    """A post-signing edit to the signed content fails verification.

    Renaming the element id breaks the reference URI ↔ target binding, so the
    digest no longer matches. gamlastan may either return an invalid result or
    raise `SamlCryptoError` (e.g. unresolvable reference) - both are correct
    "fail closed" outcomes, so we accept either.
    """
    priv, cert, cert_b64 = rsa_keypair
    template = _signature_template("_resp1", cert_b64)
    unsigned = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'ID="_resp1" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">'
        f"{template}<samlp:Status/></samlp:Response>"
    )
    signed = crypto.SamlSigner.from_pem(priv).sign_enveloped(unsigned)
    tampered = signed.replace("_resp1", "_evil1", 1)  # break the first reference target
    verifier = crypto.SamlVerifier.from_cert(cert)
    verifier.set_skip_time_checks(True, unsafe_allow_skip_time_checks=True)
    try:
        assert not verifier.verify_enveloped(tampered).is_valid()
    except pygamlastan.SamlCryptoError:
        pass


@pytest.mark.pkcs11
def test_pkcs11_signing(softhsm):
    """Genuine PKCS#11/HSM signing through the binding (SoftHSM2-gated).

    Opens a session against a provisioned SoftHSM2 token, builds an HSM-backed
    SamlSigner whose private key never leaves the token, and signs a redirect
    query. An RSA-2048 PKCS#1 v1.5 signature is exactly 256 bytes, which proves
    a real signing operation occurred. Auto-skips when SoftHSM2 is unavailable.
    """
    module, pin, label = softhsm
    prov = crypto.Pkcs11Provider(module)
    sess = prov.open_session(pin)
    hsm_signer = sess.signer(label, "rsa-sha256")
    signer = crypto.SamlSigner.with_pkcs11(hsm_signer)
    assert signer.is_hsm_backed()
    sig = signer.sign_redirect_query(
        b"SAMLRequest=abc&SigAlg=xyz",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    )
    assert len(sig) == 256  # RSA-2048


def test_redirect_signature_sha1_rejected_by_default(rsa_keypair):
    """Redirect signing and verification reject SHA-1 unless explicitly allowed."""
    priv, cert, _cert_b64 = rsa_keypair
    signer = crypto.SamlSigner.from_pem(priv)
    verifier = crypto.SamlVerifier.from_cert(cert)
    query = b"SAMLRequest=abc&SigAlg=http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1"
    sha1_uri = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"

    with pytest.raises(pygamlastan.SamlCryptoError):
        signer.sign_redirect_query(query, sha1_uri)

    sig = signer.sign_redirect_query(query, sha1_uri, unsafe_allow_weak_sha1=True)

    with pytest.raises(pygamlastan.SamlCryptoError):
        verifier.verify_redirect_query(query, sig, sha1_uri)

    assert verifier.verify_redirect_query(query, sig, sha1_uri, unsafe_allow_weak_sha1=True) is True


# --------------------------------------------------------------------------- #
# bindings
# --------------------------------------------------------------------------- #

def test_redirect_roundtrip():
    """HTTP-Redirect encode → decode preserves the message and RelayState.

    `redirect_decode` takes the *raw* (still percent-encoded) query string - the
    DEFLATE+base64+URL encoding is reversed inside gamlastan - so we hand it the
    untouched `urlparse(url).query` rather than a pre-parsed dict.
    """
    from urllib.parse import urlparse

    msg = b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" IssueInstant="2026-06-24T10:00:00Z"/>'
    url = bindings.redirect_encode(msg, True, "https://idp.example.org/sso", relay_state="state123")
    dec = bindings.redirect_decode(urlparse(url).query)
    assert dec.is_request
    assert dec.relay_state == "state123"
    assert dec.saml_text.startswith("<samlp:AuthnRequest")


def test_redirect_encode_sha1_rejection_is_binding_error(rsa_keypair):
    """Binding-level SHA-1 rejection should not wrap a crypto exception string."""
    priv, _cert, _cert_b64 = rsa_keypair
    signer = crypto.SamlSigner.from_pem(priv)
    sha1_uri = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    msg = b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" IssueInstant="2026-06-24T10:00:00Z"/>'

    with pytest.raises(pygamlastan.SamlBindingError,
                       match="SHA-1 signature algorithms") as excinfo:
        bindings.redirect_encode(
            msg, True, "https://idp.example.org/sso",
            signer=signer, sig_alg=sha1_uri,
        )
    assert "SamlCryptoError" not in str(excinfo.value)


def test_post_roundtrip():
    """HTTP-POST encode emits a self-submitting form; decode reverses it.

    POST form fields are plain base64 (no DEFLATE), so `post_decode` takes
    duplicate-preserving name/value pairs from a framework MultiDict.
    """
    msg = b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" IssueInstant="2026-06-24T10:00:00Z"/>'
    html = bindings.post_encode(msg, True, "https://idp.example.org/sso", relay_state="s2")
    assert "<form" in html and "SAMLRequest" in html
    dec = bindings.post_decode([("SAMLRequest", base64.b64encode(msg).decode()), ("RelayState", "s2")])
    assert dec.is_request and dec.relay_state == "s2"


def test_post_decode_rejects_collapsed_mapping_and_duplicates():
    """HTTP-POST decode fails closed on collapsed dict input and duplicate SAML params."""
    from collections import UserDict

    msg = b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" IssueInstant="2026-06-24T10:00:00Z"/>'
    form = {"SAMLRequest": base64.b64encode(msg).decode(), "RelayState": "s2"}
    with pytest.raises(pygamlastan.SamlBindingError):
        bindings.post_decode(form)

    dec = bindings.post_decode(form, unsafe_allow_collapsed_form=True)
    assert dec.is_request and dec.relay_state == "s2"

    user_dict = UserDict(form)
    with pytest.raises(pygamlastan.SamlBindingError):
        bindings.post_decode(user_dict)

    dec = bindings.post_decode(user_dict, unsafe_allow_collapsed_form=True)
    assert dec.is_request and dec.relay_state == "s2"

    with pytest.raises(pygamlastan.SamlBindingError):
        bindings.post_decode([("SAMLResponse", "AAAA"), ("SAMLResponse", "BBBB")])


def test_relay_state_validation():
    """RelayState over the 80-byte SAML limit is rejected (XSS/abuse guard)."""
    bindings.validate_relay_state("ok")
    with pytest.raises(pygamlastan.SamlBindingError):
        bindings.validate_relay_state("x" * (bindings.RELAY_STATE_MAX_BYTES + 1))


def test_artifact_roundtrip():
    """A type-0x0004 artifact encodes and decodes, preserving its source id.

    `matches_entity` recomputes SHA-1(entityID) and compares it to the embedded
    source id, which is how an IdP recognises its own artifacts.
    """
    art = bindings.SamlArtifact(0, IDP, bytes(range(20)))
    encoded = art.encode()
    decoded = bindings.SamlArtifact.decode(encoded)
    assert decoded.endpoint_index == 0
    assert decoded.matches_entity(IDP)
    assert len(decoded.source_id) == 20


# --------------------------------------------------------------------------- #
# metadata
# --------------------------------------------------------------------------- #

def test_metadata_parse():
    """Parsing IdP metadata exposes role, SSO endpoints and NameID formats.

    Confirms `is_idp`/`is_sp` role detection and that both advertised SSO
    bindings (Redirect + POST) are surfaced.
    """
    ed = metadata.parse_entity(SAMPLE_IDP_METADATA)
    assert ed.entity_id == IDP
    assert ed.is_idp() and not ed.is_sp()
    ssos = ed.single_sign_on_services()
    assert len(ssos) == 2
    assert {e.binding for e in ssos} == {core.BINDING_HTTP_REDIRECT, core.BINDING_HTTP_POST}
    assert core.NAMEID_TRANSIENT in ed.name_id_formats("idp")


def test_metadata_roundtrip_and_validate():
    """A parsed EntityDescriptor re-serialises to XML and passes validation."""
    ed = metadata.parse_entity(SAMPLE_IDP_METADATA)
    out = ed.to_xml()
    assert "EntityDescriptor" in out and IDP in out
    metadata.validate_entity(ed)  # MetadataValidator must not raise on valid input


def test_metadata_entities():
    """An EntitiesDescriptor aggregate is flattened to its child entities.

    The inner descriptor's redundant default-namespace declaration is stripped
    so it nests cleanly inside the aggregate wrapper.
    """
    agg = (
        '<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">'
        + SAMPLE_IDP_METADATA.replace(
            '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"',
            "<md:EntityDescriptor",
        )
        + "</md:EntitiesDescriptor>"
    )
    items = metadata.parse_entities(agg)
    assert len(items) == 1
    assert items[0].entity_id == IDP


# An SP descriptor exercising the metadata extensions: registration authority,
# entity attributes (category + subject-id:req), role-level MDUI + algsupport,
# and an AttributeConsumingService.
SAMPLE_SP_EXT_METADATA = (
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
    ' xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"'
    ' xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"'
    ' xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"'
    ' xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
    ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
    ' entityID="https://sp.example.org">'
    '<md:Extensions>'
    '<mdrpi:RegistrationInfo registrationAuthority="http://www.swamid.se/"/>'
    '<mdattr:EntityAttributes>'
    '<saml:Attribute Name="http://macedir.org/entity-category">'
    '<saml:AttributeValue>http://refeds.org/category/research-and-scholarship</saml:AttributeValue>'
    '</saml:Attribute>'
    '<saml:Attribute Name="urn:oasis:names:tc:SAML:profiles:subject-id:req">'
    '<saml:AttributeValue>any</saml:AttributeValue></saml:Attribute>'
    '</mdattr:EntityAttributes></md:Extensions>'
    '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<md:Extensions>'
    '<mdui:UIInfo>'
    '<mdui:DisplayName xml:lang="en">Example Service</mdui:DisplayName>'
    '<mdui:Logo width="80" height="60">https://example.org/logo.png</mdui:Logo>'
    '</mdui:UIInfo>'
    '<alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
    '<alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
    '</md:Extensions>'
    '<md:AssertionConsumerService'
    ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
    ' Location="https://sp.example.org/acs" index="0" isDefault="true"/>'
    '<md:AttributeConsumingService index="0">'
    '<md:ServiceName xml:lang="en">Example</md:ServiceName>'
    '<md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3"'
    ' FriendlyName="mail" isRequired="true"/>'
    '<md:RequestedAttribute Name="urn:oid:2.5.4.4" FriendlyName="sn"/>'
    '</md:AttributeConsumingService>'
    '</md:SPSSODescriptor></md:EntityDescriptor>'
)


def test_metadata_extension_accessors():
    """Registration authority, entity attributes/categories, role-level MDUI and
    algorithm support are all exposed off a parsed SP EntityDescriptor."""
    ed = metadata.parse_entity(SAMPLE_SP_EXT_METADATA)
    assert ed.registration_authority == "http://www.swamid.se/"
    assert ed.entity_categories() == ["http://refeds.org/category/research-and-scholarship"]
    assert ed.entity_attribute_values(
        "urn:oasis:names:tc:SAML:profiles:subject-id:req") == ["any"]
    assert dict(ed.entity_attributes())["http://macedir.org/entity-category"]
    # algsupport, gathered from the SPSSODescriptor Extensions (namespaces are
    # declared on the EntityDescriptor root, not the captured fragment).
    algs = ed.supported_algorithms()
    assert "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" in algs
    assert "http://www.w3.org/2001/04/xmlenc#sha256" in algs


def test_metadata_ui_info():
    """mdui:UIInfo on the SP role surfaces the display name and logo."""
    ed = metadata.parse_entity(SAMPLE_SP_EXT_METADATA)
    ui = ed.ui_info("sp")
    assert ui is not None
    assert ui.display_names == [("en", "Example Service")]
    assert len(ui.logos) == 1
    logo = ui.logos[0]
    assert logo.url == "https://example.org/logo.png"
    assert logo.width == 80 and logo.height == 60
    assert ed.ui_info("idp") is None  # no IDPSSODescriptor


def test_metadata_requested_attributes_feed_policy():
    """The SP's AttributeConsumingService requirements flow into
    ReleasePolicy.filter: required `mail` and optional `sn` are released, `cn`
    (not requested) is withheld."""
    ed = metadata.parse_entity(SAMPLE_SP_EXT_METADATA)
    required, optional = ed.requested_attributes()
    assert [a.friendly_name for a in required] == ["mail"]
    assert [a.friendly_name for a in optional] == ["sn"]

    user_attrs = [
        core.Attribute("mail", values=["a@example.org"]),
        core.Attribute("sn", values=["Doe"]),
        core.Attribute("cn", values=["Alice"]),
    ]
    out = idp.ReleasePolicy().filter(
        user_attrs, "https://sp.example.org", required=required, optional=optional)
    assert sorted(a.name for a in out) == ["mail", "sn"]


def test_create_error_response():
    """create_error_response builds an assertion-less Response with the given
    non-success status and InResponseTo."""
    resp = profiles.create_error_response(
        IDP, ACS, core.STATUS_RESPONDER, "authentication failed",
        in_response_to="_req123", now=NOW)
    assert not resp.is_success()
    assert resp.status.status_code.value == core.STATUS_RESPONDER
    assert resp.status.status_message == "authentication failed"
    assert resp.in_response_to == "_req123"
    assert resp.assertions == []


# --------------------------------------------------------------------------- #
# attribute_map
# --------------------------------------------------------------------------- #

def test_attribute_map_to_local_and_back():
    """Wire ↔ local attribute-name conversion round-trips via the default maps.

    The OID `urn:oid:0.9.2342.19200300.100.1.3` is the SAML-URI name for `mail`;
    `to_local` maps it to the friendly local name and `from_local` maps it back.
    """
    acs = attribute_map.AttributeConverterSet.with_default_maps(allow_unknown_attributes=True)
    wire = core.Attribute(
        "urn:oid:0.9.2342.19200300.100.1.3", values=["a@b.org"], name_format=core.ATTRNAME_FORMAT_URI
    )
    locals_ = acs.to_local([wire])
    assert [(la.name, la.values) for la in locals_] == [("mail", ["a@b.org"])]

    back = acs.from_local(locals_, core.ATTRNAME_FORMAT_URI)
    assert back[0].name == "urn:oid:0.9.2342.19200300.100.1.3"


def test_attribute_map_rejects_unknown_friendly_name_by_default():
    """Unknown attributes do not become local attributes via FriendlyName by default."""
    wire = core.Attribute(
        "urn:example:custom-admin-flag",
        values=["true"],
        name_format=core.ATTRNAME_FORMAT_URI,
        friendly_name="isAdmin",
    )

    strict = attribute_map.AttributeConverterSet.with_default_maps()
    assert strict.local_name(wire) is None
    assert strict.to_local([wire]) == []

    unsafe = attribute_map.AttributeConverterSet.with_default_maps(allow_unknown_attributes=True)
    assert [(la.name, la.values) for la in unsafe.to_local([wire])] == [("isAdmin", ["true"])]


def test_attribute_converter_static():
    """A single converter built from a named shipped map resolves wire→local."""
    conv = attribute_map.AttributeConverter.from_static("saml_uri")
    assert conv.to_local_name("urn:oid:0.9.2342.19200300.100.1.3") == "mail"


def test_eptid_attribute_roundtrip():
    """eduPersonTargetedID NameIDs pack into / unpack from an Attribute.

    `eptid_attribute` wraps NameIDs as the EPTID attribute (NameID-valued
    AttributeValues); `eptid_name_ids` reads them back out.
    """
    nid = core.NameId("opaque-id", format=core.NAMEID_PERSISTENT)
    attr = attribute_map.eptid_attribute([nid])
    assert attr.name == attribute_map.EPTID_OID
    ids = attribute_map.eptid_name_ids(attr)
    assert ids[0].value == "opaque-id"


# --------------------------------------------------------------------------- #
# security
# --------------------------------------------------------------------------- #

def test_security_config():
    """SecurityConfig has tunable fields and preset profiles.

    `clock_skew_seconds` is a read/write property (the Rust `#[setter]` is
    surfaced as assignment, not a `set_*` method). The `permissive()` preset
    relaxes signature requirements - for tests only, never production.
    """
    c = security.SecurityConfig()
    assert c.clock_skew_seconds > 0
    c.clock_skew_seconds = 60  # setter exposed as a property
    assert c.clock_skew_seconds == 60
    assert security.SecurityConfig.permissive().require_signed_assertions is False


def test_validate_response_structured():
    """`validate_response` returns the full 32-check result, not just pass/fail.

    Runs over a complete generated Response at the matching NOW so every check
    passes; asserts the structured result reports zero failures and that each
    individual check is marked passed (the per-check detail the error-model
    decision calls for).
    """
    parsed = xml.parse_response(_built_response_xml())
    cfg = security.SecurityConfig.permissive()
    res = security.validate_response(parsed, cfg, ACS, IDP, SP, ACS,
                                     expected_request_id="_req123", now=NOW,
                                     replay_cache=security.InMemoryReplayCache())
    assert res.is_valid()
    assert res.total_checks() > 0
    assert all(c.passed for c in res.checks)
    assert res.failures() == []


def test_validate_response_requires_replay_cache_by_default():
    """Validation requires replay protection unless the unsafe legacy mode is explicit."""
    parsed = xml.parse_response(_built_response_xml())
    cfg = security.SecurityConfig.permissive()
    with pytest.raises(pygamlastan.SamlSecurityError):
        security.validate_response(parsed, cfg, ACS, IDP, SP, ACS,
                                   expected_request_id="_req123", now=NOW)

    res = security.validate_response(
        parsed, cfg, ACS, IDP, SP, ACS,
        expected_request_id="_req123", now=NOW,
        unsafe_no_replay_cache=True,
    )
    assert res.is_valid()


def test_inmemory_replay_cache():
    """The built-in replay cache returns True once, then False for a repeat id.

    True means "newly inserted" (not seen); the second call for the same id
    within its expiry window returns False, i.e. a detected replay.

    The expiry must be in the real future: InMemoryReplayCache treats an entry as
    a replay only while its stored expiry is greater than the wall-clock
    ``Utc::now()`` (it ignores any caller-supplied clock), so a fixed past expiry
    would be seen as already expired and never flagged as a replay.
    """
    expiry = datetime.now(timezone.utc) + timedelta(seconds=300)
    cache = security.InMemoryReplayCache()
    assert cache.check_and_insert("id-1", expiry) is True
    assert cache.check_and_insert("id-1", expiry) is False


def test_python_replay_cache_protocol():
    """A pure-Python replay cache implementing the protocol is honored.

    Proves the Rust→Python store adapter: gamlastan calls `check_and_insert`
    (and `cleanup`) on an arbitrary Python object across the GIL. The first
    process_response records the assertion id; the second is rejected as a
    replay - using the application's own (here in-process) cache backend, which
    is what a multi-worker SATOSA deployment needs (Redis/DB-backed).
    """
    class PyCache:
        def __init__(self):
            self.seen = set()
            self.cleaned = 0

        def check_and_insert(self, id, expiry):
            if id in self.seen:
                return False
            self.seen.add(id)
            return True

        def cleanup(self):
            self.cleaned += 1

    cache = PyCache()
    parsed = xml.parse_response(_built_response_xml())
    cfg = security.SecurityConfig.permissive()
    # First processing succeeds and records the assertion id.
    profiles.process_response(parsed, cfg, SP, ACS, IDP, expected_request_id="_req123",
                              now=NOW, replay_cache=cache)
    assert len(cache.seen) == 1
    # Second processing is rejected as a replay.
    with pytest.raises(pygamlastan.SamlProfileError):
        profiles.process_response(parsed, cfg, SP, ACS, IDP, expected_request_id="_req123",
                                  now=NOW, replay_cache=cache)


def test_process_response_requires_replay_cache_by_default():
    """SP response processing requires a replay cache unless explicitly waived."""
    parsed = xml.parse_response(_built_response_xml())
    cfg = security.SecurityConfig.permissive()
    with pytest.raises(pygamlastan.SamlProfileError,
                       match="process_response requires replay_cache"):
        profiles.process_response(parsed, cfg, SP, ACS, IDP,
                                  expected_request_id="_req123", now=NOW)

    result = profiles.process_response(
        parsed, cfg, SP, ACS, IDP,
        expected_request_id="_req123", now=NOW,
        unsafe_no_replay_cache=True,
    )
    assert result.name_id == "alice@example.org"


def test_process_response_verified_names_replay_cache_requirement():
    """The verified entry point reports its own API name in cache errors."""
    verifier = crypto.SamlVerifier(crypto.KeysManager())
    with pytest.raises(pygamlastan.SamlProfileError,
                       match="process_response_verified requires replay_cache"):
        profiles.process_response_verified(
            "<samlp:Response/>", verifier, security.SecurityConfig(),
            SP, ACS, IDP, expected_request_id="_req123", now=NOW,
        )


# --------------------------------------------------------------------------- #
# profiles - full Web SSO round trip
# --------------------------------------------------------------------------- #

def test_create_authn_request():
    """The SP profile builds an AuthnRequest reflecting every option set.

    Checks that options flow through to the message: Issuer = SP entity id, the
    ACS URL, ForceAuthn, and the RequestedAuthnContext comparison, and that the
    result serialises to XML.
    """
    opts = profiles.AuthnRequestOptions(
        SP, acs_url=ACS, destination="https://idp.example.org/sso",
        protocol_binding=core.BINDING_HTTP_POST, name_id_format=core.NAMEID_TRANSIENT,
        authn_context_class_refs=[core.AUTHN_CONTEXT_PASSWORD], authn_context_comparison="exact",
        force_authn=True,
    )
    req = profiles.create_authn_request(opts)
    assert req.issuer.value == SP
    assert req.assertion_consumer_service_url == ACS
    assert req.force_authn is True
    assert req.requested_authn_context.comparison == "exact"
    assert "<samlp:AuthnRequest" in req.to_xml()


def test_idp_process_authn_request():
    """The IdP profile distils an incoming AuthnRequest into actionable fields.

    `process_authn_request` resolves the SP entity id (from Issuer), the ACS URL
    to respond to, and the requested NameID format - the inputs an IdP needs to
    build its Response.
    """
    req = xml.parse_authn_request(AUTHN_REQUEST)
    with pytest.raises(pygamlastan.SamlProfileError):
        profiles.process_authn_request(req)

    unsafe_processed = profiles.process_authn_request(req, unsafe_allow_missing_metadata=True)
    assert unsafe_processed.acs_url == ACS

    sp_md = metadata.parse_entity(SAMPLE_SP_METADATA)
    processed = profiles.process_authn_request(req, sp_metadata=sp_md)
    assert processed.request_id == "_req1"
    assert processed.sp_entity_id == SP
    assert processed.acs_url == ACS
    assert processed.requested_name_id_format == core.NAMEID_TRANSIENT


def test_full_sso_roundtrip():
    """End-to-end Web Browser SSO: IdP issues, SP validates and extracts.

    This is the headline integration test and the core of the
    eventually-replace-pysaml2 goal:

      1. IdP side builds a Response (subject + two attributes) for `_req123`.
      2. SP side parses it, runs the full validation suite, checks the assertion
         id against a replay cache, and returns the authenticated identity.

    The extracted NameID, issuing IdP, authn context and the flattened
    attribute dict must all match what the IdP put in.
    """
    # --- IdP side: build a signed-or-unsigned Response carrying an assertion ---
    nid = core.NameId("alice@example.org", format=core.NAMEID_TRANSIENT)
    ro = profiles.ResponseOptions(
        IDP, SP, ACS, assertion_lifetime_seconds=300, in_response_to="_req123",
        authn_context_class_ref=core.AUTHN_CONTEXT_PASSWORD,
        attributes=[core.Attribute("mail", values=["alice@example.org"]),
                    core.Attribute("displayName", values=["Alice"])],
    )
    resp = profiles.create_response(ro, nid, now=NOW)
    resp_xml = resp.to_xml()

    # --- SP side: parse + validate + extract the identity ---
    parsed = xml.parse_response(resp_xml)
    result = profiles.process_response(
        parsed, security.SecurityConfig.permissive(), SP, ACS, IDP,
        expected_request_id="_req123", now=NOW, replay_cache=security.InMemoryReplayCache(),
    )
    assert result.name_id == "alice@example.org"
    assert result.idp_entity_id == IDP
    assert result.authn_context_class_ref == core.AUTHN_CONTEXT_PASSWORD
    assert result.attributes_dict() == {"mail": ["alice@example.org"], "displayName": ["Alice"]}


def test_unsolicited_response():
    """IdP-initiated (unsolicited) Response has no InResponseTo but still binds a subject.

    Unsolicited responses answer no prior request, so `in_response_to` is None;
    the assertion still names the principal.
    """
    nid = core.NameId("bob", format=core.NAMEID_TRANSIENT)
    resp = profiles.create_unsolicited_response(
        IDP, SP, ACS, nid, attributes=[core.Attribute("mail", values=["bob@x.org"])],
        authn_context_class_ref=core.AUTHN_CONTEXT_PASSWORD, now=NOW,
    )
    parsed = xml.parse_response(resp.to_xml())
    assert parsed.in_response_to is None  # unsolicited
    assert parsed.assertions[0].subject.name_id.value == "bob"


def test_authn_instant_separate_from_issue_instant():
    """A reused SSO session authenticated earlier than the response is issued.

    Passing `authn_instant` separately keeps `AuthnStatement/@AuthnInstant`
    (real authentication time) independent of the document issue instant, so
    authentication freshness is not over-reported to SPs that enforce it. When
    omitted, `authn_instant` defaults to `now` (a fresh login).
    """
    earlier = NOW - timedelta(minutes=30)
    nid = core.NameId("carol", format=core.NAMEID_TRANSIENT)
    ro = profiles.ResponseOptions(
        IDP, SP, ACS, assertion_lifetime_seconds=300, in_response_to="_r",
        authn_context_class_ref=core.AUTHN_CONTEXT_PASSWORD,
    )
    resp = profiles.create_response(ro, nid, now=NOW, authn_instant=earlier)
    assertion = xml.parse_response(resp.to_xml()).assertions[0]
    assert assertion.issue_instant == NOW
    assert assertion.authn_statements[0].authn_instant == earlier

    # Default: both instants collapse to `now` (fresh-login behaviour).
    fresh = profiles.create_response(ro, nid, now=NOW)
    fa = xml.parse_response(fresh.to_xml()).assertions[0]
    assert fa.authn_statements[0].authn_instant == fa.issue_instant == NOW


# --------------------------------------------------------------------------- #
# idp
# --------------------------------------------------------------------------- #

def test_eptid():
    """eduPersonTargetedID is stable per (idp, sp, user) but differs across SPs.

    This is the privacy-preserving "targeted id" property: the same user gets a
    consistent opaque id at one SP, yet an unlinkable id at another. Issued as a
    persistent NameID.
    """
    ep = idp.Eptid("server-secret")
    a = ep.get(IDP, SP, "user1")
    b = ep.get(IDP, SP, "user1")
    c = ep.get(IDP, "https://other.sp", "user1")
    assert a == b           # stable per (idp, sp, user)
    assert a != c           # differs per SP (targeted)
    assert ep.name_id(IDP, SP, "user1").format == core.NAMEID_PERSISTENT


def test_authn_broker():
    """The authn broker registers methods and looks them up by class ref.

    `add` returns a unique reference and `get_by_class_ref` finds the method.
    `pick(None)` performs the "unspecified context" lookup (no requested
    context), which yields a list - we assert only its type because, with just
    a Password method registered, the unspecified/minimum match may be empty.
    """
    br = idp.AuthnBroker()
    ref = br.add(core.AUTHN_CONTEXT_PASSWORD, "pw-login", 10)
    assert ref
    m = br.get_by_class_ref(core.AUTHN_CONTEXT_PASSWORD)
    assert m.method == "pw-login" and m.level == 10
    assert m.reference == ref
    assert isinstance(br.pick(), list)  # no requested context -> unspecified lookup


def test_nameid_coding_roundtrip():
    """NameID ↔ storage-string coding round-trips for IdP persistence.

    `code_name_id` serialises a NameID to an opaque storage form that
    `decode_name_id` reverses - used to persist subject identifiers server-side.
    """
    nid = core.NameId("alice", format=core.NAMEID_TRANSIENT, name_qualifier=IDP)
    coded = idp.code_name_id(nid)
    back = idp.decode_name_id(coded)
    assert back.value == "alice"


def test_assertion_store():
    """The built-in assertion store supports put/get/remove by assertion id.

    Backs IdP features that must serve a previously issued assertion later
    (e.g. AssertionIDRequest / AuthnQuery).
    """
    store = idp.InMemoryAssertionStore()
    a = xml.parse_response(SAMPLE_RESPONSE).assertions[0]
    store.store_assertion(a)
    assert store.get_assertion("_a1").id == "_a1"
    store.remove_assertion("_a1")
    assert store.get_assertion("_a1") is None


def test_identdb_transient_and_persistent():
    """Transient NameIDs are unique per call; persistent NameIDs are stable per
    (user, SP) and resolve back to the local principal."""
    db = idp.IdentDb(IDP, domain="example.org")
    t1 = db.transient_nameid("alice", SP)
    t2 = db.transient_nameid("alice", SP)
    assert t1.value != t2.value
    assert t1.format == core.NAMEID_TRANSIENT

    p1 = db.persistent_nameid("alice", SP)
    p2 = db.persistent_nameid("alice", SP)
    assert p1.value == p2.value  # stable
    assert db.persistent_nameid("alice", "https://other.example.org").value != p1.value
    assert db.find_local_id(p1) == "alice"


def test_identdb_construct_nameid_policy():
    """`construct_nameid` honors the request NameIDPolicy format and raises
    SamlIdentError when no format can be determined."""
    db = idp.IdentDb(IDP)
    pol = core.NameIdPolicy(format=core.NAMEID_TRANSIENT, allow_create=True)
    nid = db.construct_nameid("alice", SP, pol)
    assert nid.format == core.NAMEID_TRANSIENT
    assert nid.sp_name_qualifier == SP

    with pytest.raises(pygamlastan.SamlIdentError):
        db.construct_nameid("alice", SP)  # no policy, no default_format


def test_identdb_manage_name_id():
    """Server-side ManageNameID: NewID records the SP-provided alias; Terminate
    drops the association. An unknown NameID raises SamlIdentError."""
    db = idp.IdentDb(IDP)
    nid = db.persistent_nameid("alice", SP)
    updated = db.manage_name_id_new_id(nid, "sp-alias")
    assert updated.sp_provided_id == "sp-alias"
    assert db.find_local_id(updated) == "alice"

    db.manage_name_id_terminate(updated)
    assert db.find_local_id(updated) is None

    stranger = core.NameId("nobody")
    with pytest.raises(pygamlastan.SamlIdentError):
        db.manage_name_id_terminate(stranger)


def test_identdb_python_backed_store():
    """A Python object implementing get/set/remove can back the NameID database
    (so a deployment can persist to Redis/SQL/Mongo)."""
    class DictStore:
        def __init__(self):
            self.d = {}
        def get(self, key):
            return self.d.get(key)
        def set(self, key, value):
            self.d[key] = value
        def remove(self, key):
            self.d.pop(key, None)

    backing = DictStore()
    db = idp.IdentDb(IDP, store=backing)
    nid = db.persistent_nameid("bob", SP)
    assert db.find_local_id(nid) == "bob"
    assert backing.d, "data was written through to the Python store"
    # A fresh IdentDb over the same backing store sees the persisted mapping.
    db2 = idp.IdentDb(IDP, store=backing)
    assert db2.find_local_id(nid) == "bob"


# ---------------------------------------------------------------------------
# idp - attribute-release policy + entity categories
# ---------------------------------------------------------------------------

def test_release_policy_defaults():
    """An empty ReleasePolicy returns the built-in defaults per SP."""
    pol = idp.ReleasePolicy()
    assert pol.nameid_format(SP) == core.NAMEID_TRANSIENT
    assert pol.name_form(SP) == core.ATTRNAME_FORMAT_URI
    assert pol.lifetime_seconds(SP) == 3600
    assert pol.fail_on_missing_requested(SP) is True
    assert pol.sign(SP).response is False


def test_release_policy_entity_category_refeds():
    """Entity-category release: only the R&S attributes are released to an SP
    that publishes the REFEDS Research & Scholarship category."""
    pol = idp.ReleasePolicy(default=idp.PolicyEntry(entity_categories=["refeds"]))
    attrs = [
        core.Attribute("mail", values=["a@example.org"]),
        core.Attribute("cn", values=["Alice"]),
    ]
    out = pol.filter(attrs, SP, sp_entity_categories=[idp.REFEDS_RESEARCH_AND_SCHOLARSHIP])
    assert [a.name for a in out] == ["mail"]  # cn is not in R&S


def test_release_policy_required_missing_raises():
    """A missing required attribute raises SamlPolicyError when
    fail_on_missing_requested is on (the default)."""
    pol = idp.ReleasePolicy()
    required = [core.Attribute("urn:oid:0.9.2342.19200300.100.1.3")]  # mail OID
    with pytest.raises(pygamlastan.SamlPolicyError):
        pol.filter([core.Attribute("cn", values=["x"])], SP, required=required)


def test_release_policy_value_regex_restriction():
    """Value restrictions keep only matching values (anchored, re.match-style);
    an attribute not named in the restrictions is dropped."""
    entry = idp.PolicyEntry(
        attribute_restrictions=[("mail", [r".*@example\.org"]), ("givenName", None)])
    pol = idp.ReleasePolicy(default=entry)
    attrs = [
        core.Attribute("mail", values=["a@example.org", "b@evil.com"]),
        core.Attribute("eduPersonPrincipalName", values=["x"]),
    ]
    out = pol.filter(attrs, SP)
    assert len(out) == 1
    assert out[0].name == "mail"
    assert out[0].string_values == ["a@example.org"]


def test_release_policy_subject_id_any_prefers_pairwise():
    """With subject-id:req == any and both ids present, subject-id is dropped in
    favour of the privacy-preserving pairwise-id (pysaml2 PR #987)."""
    sid = core.Attribute(idp.SUBJECT_ID_ATTR, values=["alice"], friendly_name="subject-id")
    pid = core.Attribute(idp.PAIRWISE_ID_ATTR, values=["opaque"], friendly_name="pairwise-id")
    out = idp.ReleasePolicy().filter(
        [sid, pid, core.Attribute("mail", values=["m"])], SP, subject_id_req="any")
    friendly = {a.friendly_name or a.name for a in out}
    assert "pairwise-id" in friendly
    assert "subject-id" not in friendly


def test_release_policy_custom_entity_category():
    """A developer-defined (owned) entity category releases its attributes when
    the SP publishes the custom category URI."""
    rule = idp.EntityCategoryRule(["https://eduid.se/category/staff"], ["mail"])
    custom = idp.EntityCategoryPolicy("eduid-local", rules=[rule])
    pol = idp.ReleasePolicy(default=idp.PolicyEntry(owned_entity_categories=[custom]))
    attrs = [core.Attribute("mail", values=["a@x"]), core.Attribute("cn", values=["A"])]
    out = pol.filter(attrs, SP, sp_entity_categories=["https://eduid.se/category/staff"])
    assert [a.name for a in out] == ["mail"]

    # releasable_attributes exposes the engine directly.
    assert idp.releasable_attributes([custom], ["https://eduid.se/category/staff"]) == ["mail"]


def test_release_policy_registration_authority_from_metadata():
    """register_sp_metadata reads RegistrationInfo/@registrationAuthority so an
    SP with no entry of its own resolves to its registration-authority entry."""
    sp_md = (
        '<?xml version="1.0"?>'
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
        ' xmlns:mdrpi="urn:oasis:names:tc:SAML:metadata:rpi"'
        ' entityID="https://sp.swamid.example">'
        '<md:Extensions><mdrpi:RegistrationInfo'
        ' registrationAuthority="http://www.swamid.se/"/></md:Extensions>'
        '<md:SPSSODescriptor protocolSupportEnumeration='
        '"urn:oasis:names:tc:SAML:2.0:protocol">'
        '<md:AssertionConsumerService'
        ' Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
        ' Location="https://sp.swamid.example/acs" index="0"/>'
        '</md:SPSSODescriptor></md:EntityDescriptor>'
    )
    ed = metadata.parse_entity(sp_md)
    pol = idp.ReleasePolicy()
    pol.insert("default", idp.PolicyEntry(lifetime_seconds=3600))
    pol.insert("http://www.swamid.se/", idp.PolicyEntry(lifetime_seconds=600))
    pol.register_sp_metadata(ed)
    assert pol.lifetime_seconds("https://sp.swamid.example") == 600  # RA entry
    assert pol.lifetime_seconds("https://unknown.example") == 3600  # default


def test_sign_targets_resolve():
    """SignTargets.resolve folds the on-demand flag against the SP's
    WantAssertionsSigned."""
    st = idp.SignTargets(response=True, on_demand=True)
    assert st.resolve(True).sign_response is True
    assert st.resolve(True).sign_assertion is True
    assert st.resolve(False).sign_assertion is False


# --------------------------------------------------------------------------- #
# Security-hardening regression tests (differential-review fixes)
#
# These pin down the behaviour of the fixes applied after the security review:
# the verify-internally SP entry point (F-1), the permissive/downgrade warnings
# (F-3), HTTP Parameter Pollution rejection in redirect_decode (F-4), and the
# CSPRNG-backed artifact constructor (F-5).
# --------------------------------------------------------------------------- #

def _signed_built_response_xml(cert_b64, priv, in_response_to="_req123"):
    """A complete, *signed* SAML Response: the IdP profile output with an
    enveloped XML-DSig over the Response root spliced in and filled by the signer.
    """
    nid = core.NameId("alice@example.org", format=core.NAMEID_TRANSIENT)
    ro = profiles.ResponseOptions(
        IDP, SP, ACS, assertion_lifetime_seconds=300, in_response_to=in_response_to,
        authn_context_class_ref=core.AUTHN_CONTEXT_PASSWORD,
        attributes=[core.Attribute("mail", values=["alice@example.org"])],
    )
    resp = profiles.create_response(ro, nid, now=NOW)
    unsigned = resp.to_xml()
    template = _signature_template(resp.id, cert_b64)
    # The enveloped Signature must sit right after the Response <saml:Issuer>
    # (the first Issuer in the doc is the Response's, before the Assertion's).
    marker = "</saml:Issuer>"
    idx = unsigned.index(marker) + len(marker)
    spliced = unsigned[:idx] + template + unsigned[idx:]
    return crypto.SamlSigner.from_pem(priv).sign_enveloped(spliced)


def test_process_response_verified_accepts_signed(rsa_keypair):
    """`process_response_verified` accepts a correctly signed Response and
    extracts identity - the safe path that binds validation to real crypto."""
    _priv_cert = rsa_keypair
    priv, cert, cert_b64 = _priv_cert
    signed = _signed_built_response_xml(cert_b64, priv)
    verifier = crypto.SamlVerifier.from_cert(cert)
    result = profiles.process_response_verified(
        signed, verifier, security.SecurityConfig.permissive(),
        SP, ACS, IDP, expected_request_id="_req123", now=NOW,
        replay_cache=security.InMemoryReplayCache(),
    )
    assert result.name_id == "alice@example.org"
    assert result.idp_entity_id == IDP


def test_process_response_verified_rejects_unsigned(rsa_keypair):
    """The F-1 guard: an UNSIGNED (but otherwise complete) Response cannot pass
    the verify-internally path. There is no signature to verify, so the call
    raises instead of silently trusting it - closing the auth-bypass gap where a
    caller could assert `verified_signed_ids` it never actually verified."""
    priv, cert, _cert_b64 = rsa_keypair
    unsigned = _built_response_xml()
    verifier = crypto.SamlVerifier.from_cert(cert)
    with pytest.raises(pygamlastan.SamlCryptoError):
        profiles.process_response_verified(
            unsigned, verifier, security.SecurityConfig.permissive(),
            SP, ACS, IDP, expected_request_id="_req123", now=NOW,
            replay_cache=security.InMemoryReplayCache(),
        )


def test_process_response_verified_rejects_tampered(rsa_keypair):
    """A post-signing edit to the signed Response fails the verify path."""
    priv, cert, cert_b64 = rsa_keypair
    signed = _signed_built_response_xml(cert_b64, priv)
    # Flip an attribute value after signing: the digest no longer matches.
    tampered = signed.replace("alice@example.org", "attacker@evil.org")
    verifier = crypto.SamlVerifier.from_cert(cert)
    with pytest.raises(pygamlastan.SamlError):
        profiles.process_response_verified(
            tampered, verifier, security.SecurityConfig.permissive(),
            SP, ACS, IDP, expected_request_id="_req123", now=NOW,
            replay_cache=security.InMemoryReplayCache(),
        )


def test_permissive_config_warns():
    """`SecurityConfig.permissive()` emits a UserWarning (F-3)."""
    with pytest.warns(UserWarning, match="permissive"):
        security.SecurityConfig.permissive()


def test_verifier_downgrade_setters_warn():
    """Verifier downgrade knobs block by default and warn only with unsafe flags."""
    import warnings

    verifier = crypto.SamlVerifier(crypto.KeysManager())
    with pytest.raises(pygamlastan.SamlCryptoError):
        verifier.set_trusted_keys_only(False)
    with pytest.raises(pygamlastan.SamlCryptoError):
        verifier.set_strict_verification(False)
    with pytest.raises(pygamlastan.SamlCryptoError):
        verifier.set_skip_time_checks(True)

    with pytest.warns(UserWarning, match="trusted_keys_only"):
        verifier.set_trusted_keys_only(False, unsafe_allow_untrusted_keys=True)
    with pytest.warns(UserWarning, match="strict_verification"):
        verifier.set_strict_verification(False, unsafe_allow_non_strict=True)
    with pytest.warns(UserWarning, match="skip_time_checks"):
        verifier.set_skip_time_checks(True, unsafe_allow_skip_time_checks=True)
    # Secure direction: no warning.
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        verifier.set_trusted_keys_only(True)
        verifier.set_strict_verification(True)
        verifier.set_skip_time_checks(False)


def test_redirect_decode_rejects_duplicate_params():
    """F-4: duplicate signature-relevant query params are rejected rather than
    silently last-wins'd (HTTP Parameter Pollution / signature-wrapping guard)."""
    with pytest.raises(pygamlastan.SamlBindingError):
        bindings.redirect_decode("SAMLResponse=AAAA&SAMLResponse=BBBB")
    with pytest.raises(pygamlastan.SamlBindingError):
        bindings.redirect_decode("SAMLResponse=AAAA&SigAlg=x&Signature=a&Signature=b")
    # A single occurrence of each is still fine (non-security dup keys untouched).
    dec = bindings.redirect_decode(
        bindings.redirect_encode(
            b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'ID="_r1" Version="2.0" IssueInstant="2026-06-24T10:00:00Z"/>',
            True, "https://idp.example.org/sso",
        ).split("?", 1)[1]
    )
    assert dec.is_request


def test_artifact_generate_is_random():
    """F-5: `SamlArtifact.generate` fills a 20-byte CSPRNG handle; two artifacts
    for the same entity differ, and the artifact still round-trips."""
    a = bindings.SamlArtifact.generate(0, IDP)
    b = bindings.SamlArtifact.generate(0, IDP)
    assert len(a.message_handle) == 20
    assert a.message_handle != b.message_handle  # CSPRNG, not a constant
    assert a.matches_entity(IDP)
    assert bindings.SamlArtifact.decode(a.encode()).message_handle == a.message_handle


# --------------------------------------------------------------------------- #
# Profile-building surface: full SecurityConfig, persistent-id store, individual
# checks. These back the "writing a new SAML profile" docs.
# --------------------------------------------------------------------------- #

def test_security_config_all_fields_tunable():
    """Every gamlastan SecurityConfig knob is individually gettable/settable, so
    a new profile can tune policy without relying on the strict/permissive
    presets."""
    cfg = security.SecurityConfig()
    for field in [
        "require_encrypted_assertions",
        "reject_signatures_with_ds_object",
        "enforce_persistent_id_uniqueness",
        "sanitize_relay_state",
        "require_integrity_with_cbc",
        "check_client_address",
    ]:
        before = getattr(cfg, field)
        setattr(cfg, field, not before)
        assert getattr(cfg, field) is (not before), field


def test_persistent_id_store_detects_reassignment():
    """E78: a persistent NameID rebound to a different principal is rejected by
    the validator when a persistent-id store is supplied (F-2 / Task 2)."""
    class DictPidStore:
        def __init__(self):
            self.seen = {}

        def check_and_record(self, name_id, sp_entity_id, principal):
            key = (name_id, sp_entity_id)
            existing = self.seen.get(key)
            if existing is None:
                self.seen[key] = principal
                return True
            return existing == principal  # False => conflict

    store = DictPidStore()
    cfg = security.SecurityConfig.permissive()
    cfg.enforce_persistent_id_uniqueness = True
    assert cfg.enforce_persistent_id_uniqueness is True
    parsed = xml.parse_response(_built_response_xml(
        name_id_value="p-alice",
        name_id_format=core.NAMEID_PERSISTENT,
    ))

    with pytest.raises(pygamlastan.SamlSecurityError):
        security.validate_response(
            parsed, cfg, ACS, IDP, SP, ACS,
            expected_request_id="_req123", now=NOW,
            replay_cache=security.InMemoryReplayCache(),
        )

    res = security.validate_response(
        parsed, cfg, ACS, IDP, SP, ACS,
        expected_request_id="_req123", now=NOW,
        replay_cache=security.InMemoryReplayCache(),
        persistent_id_store=store,
    )
    assert res.is_valid()
    store.seen[("p-alice", SP)] = "mallory"

    conflict = security.validate_response(
        parsed, cfg, ACS, IDP, SP, ACS,
        expected_request_id="_req123", now=NOW,
        replay_cache=security.InMemoryReplayCache(),
        persistent_id_store=store,
    )
    assert not conflict.is_valid()

    with pytest.raises(pygamlastan.SamlProfileError):
        profiles.process_response(
            parsed, cfg, SP, ACS, IDP,
            expected_request_id="_req123", now=NOW,
            replay_cache=security.InMemoryReplayCache(),
        )

    result = profiles.process_response(
        parsed, cfg, SP, ACS, IDP,
        expected_request_id="_req123", now=NOW,
        replay_cache=security.InMemoryReplayCache(),
        persistent_id_store=DictPidStore(),
    )
    assert result.name_id == "p-alice"


def test_individual_check_assertion_age():
    """`check_assertion_age` runs one check standalone; `ValidationResult.get` /
    `.by_name` pull a specific outcome out of a full run (Task 3)."""
    cfg = security.SecurityConfig()
    cfg.max_assertion_age_seconds = 300
    fresh = security.check_assertion_age(cfg, NOW, NOW)
    assert fresh.passed is True
    stale_issue = datetime(2026, 6, 25, 9, 0, 0, tzinfo=timezone.utc)  # 1h before NOW
    stale = security.check_assertion_age(cfg, stale_issue, NOW)
    assert stale.passed is False

    # Individual outcomes are addressable from a full validation run.
    parsed = xml.parse_response(_built_response_xml())
    res = security.validate_response(
        parsed, security.SecurityConfig.permissive(), ACS, IDP, SP, ACS,
        expected_request_id="_req123", now=NOW,
        replay_cache=security.InMemoryReplayCache(),
    )
    assert res.total_checks() == len(res.checks)
    assert len(res.passed_checks()) + len(res.failures()) == res.total_checks()
    first = res.checks[0]
    assert res.get(first.check_number).check_name == first.check_name
    assert res.by_name(first.check_name).check_number == first.check_number


# ---------------------------------------------------------------------------
# logout - Single Logout (SLO)
# ---------------------------------------------------------------------------

def _slo_name_id():
    return core.NameId("user@example.com", format=core.NAMEID_EMAIL)


def test_create_sp_logout_request():
    """An SP-initiated LogoutRequest carries the SP issuer, NameID, session
    indexes, reason, and a default NotOnOrAfter window."""
    opts = logout.SpLogoutRequestOptions(
        SP,
        _slo_name_id(),
        session_indexes=["_sess1"],
        reason=logout.REASON_USER,
        destination=f"{IDP}/slo",
    )
    req = logout.create_sp_logout_request(opts)
    assert req.id.startswith("_")
    assert req.issuer.value == SP
    assert req.name_id.value == "user@example.com"
    assert req.session_indexes == ["_sess1"]
    assert req.reason == logout.REASON_USER
    # Round-trips through XML and back.
    reparsed = xml.parse_logout_request(req.to_xml())
    assert reparsed.issuer.value == SP
    assert reparsed.session_indexes == ["_sess1"]


def test_logout_response_builders():
    """Success, partial, and error LogoutResponses set the expected status."""
    ok = logout.create_logout_response_success(IDP, "_req1", f"{SP}/slo")
    assert ok.is_success()
    assert ok.in_response_to == "_req1"

    partial = logout.create_logout_response_partial(IDP, "_req1")
    assert partial.is_success()  # top-level Success ...
    assert "PartialLogout" in partial.status.status_code.sub_status.value  # ... w/ sub-status

    err = logout.create_logout_response_error(IDP, "_req1", core.STATUS_RESPONDER, "boom")
    assert not err.is_success()
    assert err.status.status_code.value == core.STATUS_RESPONDER
    assert err.status.status_message == "boom"


def test_validate_logout_request():
    """`validate_logout_request` accepts a fresh request and rejects an expired
    one (raising SamlProfileError)."""
    opts = logout.SpLogoutRequestOptions(SP, _slo_name_id())
    req = logout.create_sp_logout_request(opts)
    logout.validate_logout_request(req, datetime.now(timezone.utc), 180)  # no raise

    # An expired request (NotOnOrAfter in the past) is rejected.
    past = datetime.now(timezone.utc) - timedelta(minutes=10)
    expired_opts = logout.SpLogoutRequestOptions(SP, _slo_name_id(), not_on_or_after=past)
    expired = logout.create_sp_logout_request(expired_opts)
    with pytest.raises(pygamlastan.SamlProfileError):
        logout.validate_logout_request(expired, datetime.now(timezone.utc), 180)


def test_orchestrator_full_success():
    """The SP orchestrator drives request->response per target until complete."""
    orch = logout.SpLogoutOrchestrator(SP)
    orch.add_target(
        logout.LogoutTarget("https://idp1.example.org", _slo_name_id(),
                            "https://idp1.example.org/slo", core.BINDING_SOAP,
                            session_indexes=["_sess1"]))
    orch.add_target(
        logout.LogoutTarget("https://idp2.example.org", _slo_name_id(),
                            "https://idp2.example.org/slo", core.BINDING_SOAP))
    assert not orch.is_complete()

    while True:
        pending = orch.next_request()
        if pending is None:
            break
        assert pending.request.issuer.value == SP
        resp = logout.create_logout_response_success(
            pending.entity_id, pending.request.id, f"{SP}/slo")
        outcome = orch.handle_response(resp)
        assert outcome.success and not outcome.partial

    assert orch.is_complete()
    prog = orch.progress()
    assert prog.total_participants == 2
    assert prog.successful_logouts == 2
    assert prog.is_complete()
    assert orch.target_state("https://idp1.example.org").kind == "succeeded"


def test_orchestrator_partial_and_failure():
    """A PartialLogout response and a transport failure both mark targets failed,
    and the orchestrator still reaches completion."""
    orch = logout.SpLogoutOrchestrator(SP)
    orch.add_target(
        logout.LogoutTarget("https://idp1.example.org", _slo_name_id(),
                            "https://idp1.example.org/slo", core.BINDING_SOAP))
    orch.add_target(
        logout.LogoutTarget("https://idp2.example.org", _slo_name_id(),
                            "https://idp2.example.org/slo", core.BINDING_SOAP))

    p1 = orch.next_request()
    partial = logout.create_logout_response_partial("https://idp1.example.org", p1.request.id)
    out1 = orch.handle_response(partial)
    assert out1.success and out1.partial
    state1 = orch.target_state("https://idp1.example.org")
    assert state1.kind == "failed"  # partial logout is not a clean success

    p2 = orch.next_request()
    orch.mark_failed(p2.entity_id, "connection refused")

    assert orch.is_complete()
    prog = orch.progress()
    assert prog.successful_logouts == 0
    assert len(prog.failed_participants) == 2


def test_orchestrator_rejects_issuer_mismatch():
    """A LogoutResponse whose issuer does not match the target entity is
    rejected (anti-spoofing: InResponseTo alone is insufficient)."""
    orch = logout.SpLogoutOrchestrator(SP)
    orch.add_target(
        logout.LogoutTarget("https://idp1.example.org", _slo_name_id(),
                            "https://idp1.example.org/slo", core.BINDING_SOAP))
    pending = orch.next_request()
    spoofed = logout.create_logout_response_success(
        "https://evil.example.org", pending.request.id)
    with pytest.raises(pygamlastan.SamlProfileError):
        orch.handle_response(spoofed)
