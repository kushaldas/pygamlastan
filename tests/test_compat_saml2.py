"""Tests for the pysaml2 compatibility shim (``pygamlastan.compat.saml2``).

These mirror the eduID SP flow without the Flask/Mongo stack: build an
AuthnRequest, feed back a Response, read pysaml2-shaped ``session_info``,
round-trip the NameID via ``code``/``decode``, and exercise the Single Logout
helpers and SP metadata generation. Both unsigned (dev) and signed-response
handling are covered here (see the ``test_signed_response_*`` cases); the full
eduID integration is verified separately in the eduid-developer env.
"""

import base64
import urllib.parse
from datetime import datetime, timedelta, timezone

import pytest

from pygamlastan import bindings as pgbindings
from pygamlastan import crypto, metadata as md
from pygamlastan import xml as pgxml
from pygamlastan.compat import saml2
from pygamlastan.compat.saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from pygamlastan.compat.saml2.client import Saml2Client
from pygamlastan.compat.saml2.config import SPConfig
from pygamlastan.compat.saml2.ident import code, decode
from pygamlastan.compat.saml2.metadata import entity_descriptor
from pygamlastan.compat.saml2.response import StatusError, UnsolicitedResponse
from pygamlastan.compat.saml2.s_utils import (
    decode_base64_and_inflate,
    deflate_and_base64_encode,
)
from pygamlastan.compat.saml2.saml import NameID

SP = "http://test.localhost:6544/saml2-metadata"
ACS = "http://test.localhost:6544/saml2-acs"
SLO = "http://test.localhost:6544/saml2-ls"
IDP = "https://idp.example.com/simplesaml/saml2/idp/metadata.php"
SSO = "https://idp.example.com/simplesaml/saml2/idp/SSOService.php"
IDPSLO = "https://idp.example.com/simplesaml/saml2/idp/SingleLogoutService.php"
PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

CONF = {
    "entityid": SP,
    "service": {
        "sp": {
            "name": "Test SP",
            "endpoints": {
                "assertion_consumer_service": [(ACS, BINDING_HTTP_POST)],
                "single_logout_service": [(SLO, BINDING_HTTP_REDIRECT)],
            },
            "want_response_signed": False,
            "idp": {
                IDP: {
                    "single_sign_on_service": {BINDING_HTTP_REDIRECT: SSO},
                    "single_logout_service": {BINDING_HTTP_REDIRECT: IDPSLO},
                }
            },
        }
    },
    # Keys eduID's settings set that the shim must accept and ignore:
    "xmlsec_binary": "/usr/bin/xmlsec1",
    "attribute_map_dir": "/nonexistent",
    "debug": 1,
}


def _auth_response(req_id: str) -> str:
    now = datetime.now(timezone.utc)
    ts = (now - timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    tomorrow = (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"""<?xml version='1.0' encoding='UTF-8'?>
<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{ACS}" ID="id-resp-1" InResponseTo="{req_id}" IssueInstant="{ts}" Version="2.0">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{IDP}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="id-assert-1" IssueInstant="{ts}" Version="2.0">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{IDP}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="{TRANSIENT}" SPNameQualifier="{SP}">abc123hash</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="{req_id}" NotOnOrAfter="{tomorrow}" Recipient="{ACS}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{yesterday}" NotOnOrAfter="{tomorrow}">
      <saml:AudienceRestriction><saml:Audience>{SP}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{ts}" SessionIndex="{req_id}">
      <saml:AuthnContext><saml:AuthnContextClassRef>{PPT}</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" FriendlyName="eduPersonPrincipalName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>hubba-bubba@eduid.se</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"><saml:AttributeValue>hubba@eduid.se</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""


def _logout_response(req_id: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"""<?xml version='1.0' encoding='UTF-8'?>
<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-lr-1" InResponseTo="{req_id}" IssueInstant="{ts}" Version="2.0" Destination="{SLO}">
  <saml:Issuer>{IDP}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
</samlp:LogoutResponse>"""


def _logout_request(req_id: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"""<?xml version='1.0' encoding='UTF-8'?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{req_id}" IssueInstant="{ts}" Version="2.0" Destination="{SLO}">
  <saml:Issuer>{IDP}</saml:Issuer>
  <saml:NameID Format="{TRANSIENT}" SPNameQualifier="{SP}">abc123hash</saml:NameID>
  <samlp:SessionIndex>session-1</samlp:SessionIndex>
</samlp:LogoutRequest>"""


def _failed_response(req_id: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"""<?xml version='1.0' encoding='UTF-8'?>
<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{ACS}" ID="id-resp-fail" InResponseTo="{req_id}" IssueInstant="{ts}" Version="2.0">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{IDP}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/></samlp:Status>
</samlp:Response>"""


def _signature_template(elem_id: str, cert_b64: str) -> str:
    """Enveloped XML-DSig template gamlastan fills in when signing ``elem_id``."""
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


def _signed_auth_response(req_id: str, cert_b64: str, priv: bytes) -> str:
    """The test AuthnResponse with an enveloped signature over the Response root."""
    unsigned = _auth_response(req_id)
    template = _signature_template("id-resp-1", cert_b64)
    marker = "</saml:Issuer>"  # the Response's Issuer is the first in the doc
    idx = unsigned.index(marker) + len(marker)
    spliced = unsigned[:idx] + template + unsigned[idx:]
    return crypto.SamlSigner.from_pem(priv).sign_enveloped(spliced)


def _idp_metadata(cert_der_b64: str) -> str:
    return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{cert_der_b64}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="{BINDING_HTTP_REDIRECT}" Location="{IDPSLO}"/>
    <md:SingleSignOnService Binding="{BINDING_HTTP_REDIRECT}" Location="{SSO}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""


@pytest.fixture
def client() -> Saml2Client:
    return Saml2Client(SPConfig().load(CONF))


def test_bindings_are_saml_urns():
    assert saml2.BINDING_HTTP_POST.endswith("HTTP-POST")
    assert saml2.BINDING_HTTP_REDIRECT.endswith("HTTP-Redirect")


def test_spconfig_load_and_only_idp():
    cfg = SPConfig().load(CONF)
    assert cfg.entityid == SP
    assert cfg.only_idp() == IDP
    assert cfg.single_sign_on_service(IDP, BINDING_HTTP_REDIRECT) == SSO
    assert cfg.single_logout_service(IDP, BINDING_HTTP_REDIRECT) == IDPSLO
    assert cfg.want_response_signed is False


def test_prepare_for_authenticate_redirect(client):
    session_id, info = client.prepare_for_authenticate(
        entityid=IDP,
        relay_state="state-xyz",
        binding=BINDING_HTTP_REDIRECT,
        force_authn="true",
        requested_authn_context={"authn_context_class_ref": [PPT], "comparison": "exact"},
    )
    assert info["headers"][0][0] == "Location"
    assert info["headers"][0][1].startswith(SSO + "?SAMLRequest=")
    assert session_id  # the AuthnRequest ID, echoed back as InResponseTo


def test_prepare_for_authenticate_unknown_idp_raises():
    # An SP with two configured IdPs and no explicit entityid is ambiguous;
    # pysaml2 raises TypeError, which eduID relies on.
    conf = {**CONF}
    conf["service"] = {"sp": {**CONF["service"]["sp"], "idp": {IDP: {}, "https://other/idp": {}}}}
    client = Saml2Client(SPConfig().load(conf))
    with pytest.raises(TypeError):
        client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)


def test_parse_authn_response_session_info(client):
    session_id, _ = client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)
    raw = base64.b64encode(_auth_response(session_id).encode("utf-8")).decode("ascii")
    resp = client.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "ref-1"})

    assert resp.session_id() == session_id
    si = resp.session_info()
    assert si["issuer"] == IDP
    assert si["ava"]["eduPersonPrincipalName"] == ["hubba-bubba@eduid.se"]
    assert si["ava"]["mail"] == ["hubba@eduid.se"]
    assert si["session_index"] == session_id
    assert si["authn_info"][0][0] == PPT
    datetime.fromisoformat(si["authn_info"][0][2])  # authn instant is parseable
    assert isinstance(si["name_id"], NameID)
    assert si["name_id"].text == "abc123hash"
    assert si["name_id"].format == TRANSIENT


def test_parse_authn_response_unsolicited_rejected(client):
    session_id, _ = client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)
    raw = base64.b64encode(_auth_response(session_id).encode("utf-8")).decode("ascii")
    with pytest.raises(UnsolicitedResponse):
        client.parse_authn_request_response(raw, BINDING_HTTP_POST, {"some-other-id": "ref"})


def test_name_id_code_decode_round_trip():
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    coded = code(nid)
    assert isinstance(coded, str)
    back = decode(coded)
    assert back.text == "abc123hash"
    assert back.format == TRANSIENT
    assert back.sp_name_qualifier == SP


def test_s_utils_deflate_round_trip():
    payload = "<x>hej hej</x>"
    assert decode_base64_and_inflate(deflate_and_base64_encode(payload)).decode() == payload


def test_global_logout_builds_redirect(client):
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    logouts = client.global_logout(nid)
    assert IDP in logouts
    req_id, info = logouts[IDP]
    assert req_id
    assert info["headers"][0][1].startswith(IDPSLO + "?SAMLRequest=")


def test_parse_logout_request_response_status_ok(client):
    encoded = deflate_and_base64_encode(_logout_response("req-1"))
    resp = client.parse_logout_request_response(encoded, BINDING_HTTP_REDIRECT)
    assert resp.status_ok() is True


def test_handle_logout_request_redirects_to_idp(client):
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    encoded = deflate_and_base64_encode(_logout_request("id-idp-logout-1"))
    info = client.handle_logout_request(encoded, nid, BINDING_HTTP_REDIRECT, relay_state="rs")
    assert info["headers"][0][1].startswith(IDPSLO + "?SAMLResponse=")


def test_handle_logout_request_rejects_mismatched_subject(client):
    """A LogoutRequest for a different subject than the session must fail closed."""
    other = NameID(text="someone-else", format=TRANSIENT, sp_name_qualifier=SP)
    encoded = deflate_and_base64_encode(_logout_request("id-idp-logout-mismatch"))
    with pytest.raises(ValueError, match="does not match the session NameID"):
        client.handle_logout_request(encoded, other, BINDING_HTTP_REDIRECT)


def test_handle_logout_request_rejects_stale_request(client):
    """An expired LogoutRequest (NotOnOrAfter in the past) cannot be replayed."""
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stale = f"""<?xml version='1.0' encoding='UTF-8'?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-stale" IssueInstant="{ts}" NotOnOrAfter="{past}" Version="2.0" Destination="{SLO}">
  <saml:Issuer>{IDP}</saml:Issuer>
  <saml:NameID Format="{TRANSIENT}" SPNameQualifier="{SP}">abc123hash</saml:NameID>
</samlp:LogoutRequest>"""
    encoded = deflate_and_base64_encode(stale)
    with pytest.raises(ValueError, match="invalid LogoutRequest"):
        client.handle_logout_request(encoded, nid, BINDING_HTTP_REDIRECT)


def test_handle_logout_request_wraps_decode_errors(client):
    """Undecodable transport (not valid base64/DEFLATE) surfaces as ValueError."""
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    with pytest.raises(ValueError, match="invalid LogoutRequest"):
        client.handle_logout_request("!!!not-base64!!!", nid, BINDING_HTTP_REDIRECT)


def test_nameid_rejects_non_string_field():
    """NameID validates field types upfront rather than crashing later."""
    with pytest.raises(TypeError, match="NameID.format"):
        NameID(text="abc", format=123)  # type: ignore[arg-type]


def test_entity_descriptor_parses_back():
    cfg = SPConfig().load(CONF)
    xml = entity_descriptor(cfg).to_xml()
    ed = md.parse_entity(xml)
    assert ed.entity_id == SP
    assert ed.is_sp()
    assert any(e.location == ACS for e in ed.assertion_consumer_services())
    assert any(e.location == SLO for e in ed.single_logout_services("sp"))


# --------------------------------------------------------------------------- #
# Closer pysaml2-contract parity tests
# --------------------------------------------------------------------------- #

def test_session_info_has_pysaml2_keys(client):
    """session_info reproduces pysaml2's documented key set exactly."""
    session_id, _ = client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)
    raw = base64.b64encode(_auth_response(session_id).encode("utf-8")).decode("ascii")
    si = client.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"}).session_info()
    assert set(si) == {
        "ava",
        "name_id",
        "came_from",
        "issuer",
        "not_on_or_after",
        "authn_info",
        "session_index",
    }
    # authn_info is a list of (class_ref, [authorities], instant) triples.
    entry = si["authn_info"][0]
    assert len(entry) == 3
    assert isinstance(entry[1], list)


def test_prepare_request_roundtrips_and_carries_options(client):
    """The encoded SAMLRequest is a real AuthnRequest whose ID is the returned
    session_id and which carries ForceAuthn / RequestedAuthnContext / ACS URL."""
    session_id, info = client.prepare_for_authenticate(
        entityid=IDP,
        binding=BINDING_HTTP_REDIRECT,
        force_authn="true",
        requested_authn_context={"authn_context_class_ref": [PPT], "comparison": "exact"},
    )
    query = info["headers"][0][1].split("?", 1)[1]
    decoded = pgbindings.redirect_decode(query)
    assert decoded.is_request
    req = pgxml.parse_authn_request(decoded.saml_text)
    assert req.id == session_id
    assert req.force_authn is True
    assert req.assertion_consumer_service_url == ACS
    rac = req.requested_authn_context
    assert rac is not None and PPT in rac.authn_context_class_refs


def test_prepare_post_binding(client):
    _session_id, info = client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_POST)
    assert info["method"] == "POST"
    assert info["url"] == SSO
    assert "SAMLRequest" in info["data"]  # auto-submit form body


def test_prepare_relay_state_present(client):
    _session_id, info = client.prepare_for_authenticate(
        entityid=IDP, relay_state="hello world", binding=BINDING_HTTP_REDIRECT
    )
    query = info["headers"][0][1].split("?", 1)[1]
    params = dict(urllib.parse.parse_qsl(query))
    assert params["RelayState"] == "hello world"


@pytest.mark.parametrize(
    "value,expected",
    [("true", True), ("false", False), (True, True), (False, False), ("1", True)],
)
def test_force_authn_variants(client, value, expected):
    session_id, info = client.prepare_for_authenticate(
        entityid=IDP, binding=BINDING_HTTP_REDIRECT, force_authn=value
    )
    query = info["headers"][0][1].split("?", 1)[1]
    req = pgxml.parse_authn_request(pgbindings.redirect_decode(query).saml_text)
    # gamlastan only emits ForceAuthn when true; absent reads back as False/None.
    assert bool(req.force_authn) is expected


def test_status_error_on_failed_response(client):
    session_id, _ = client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)
    raw = base64.b64encode(_failed_response(session_id).encode("utf-8")).decode("ascii")
    with pytest.raises(StatusError):
        client.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})


def test_decode_rejects_foreign_string():
    # Strings not produced by this shim's code() are rejected (we control both
    # ends; a foreign value means a corrupt/incompatible session).
    with pytest.raises(ValueError):
        decode("0=foo,2=urn:something")


def test_ava_multivalue_and_extra_attributes():
    """ava conversion handles multiple attributes and multi-valued attributes."""
    from pygamlastan import attribute_map, core

    conv = attribute_map.AttributeConverterSet.with_default_maps()
    attrs = [
        core.Attribute(
            "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
            values=["staff@eduid.se", "member@eduid.se"],
            name_format=core.ATTRNAME_FORMAT_URI,
        ),
        core.Attribute(
            "urn:oid:2.16.840.1.113730.3.1.241",
            values=["Hubba Bubba"],
            name_format=core.ATTRNAME_FORMAT_URI,
        ),
    ]
    ava = {la.name: list(la.values) for la in conv.to_local(attrs)}
    assert ava["eduPersonScopedAffiliation"] == ["staff@eduid.se", "member@eduid.se"]
    assert ava["displayName"] == ["Hubba Bubba"]


# --------------------------------------------------------------------------- #
# Signed-response path (what real eduID deployments use)
# --------------------------------------------------------------------------- #

def _signed_client(tmp_path, cert_der_b64):
    md_path = tmp_path / "idp_metadata.xml"
    md_path.write_text(_idp_metadata(cert_der_b64), encoding="utf-8")
    conf = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(ACS, BINDING_HTTP_POST)],
                    "single_logout_service": [(SLO, BINDING_HTTP_REDIRECT)],
                },
                # want_response_signed omitted -> defaults to True (signed required)
            }
        },
        "metadata": {"local": [str(md_path)]},
    }
    cfg = SPConfig().load(conf)
    return Saml2Client(cfg)


def test_signed_response_accepted(rsa_keypair, tmp_path):
    """want_response_signed=True: a correctly signed Response verifies against the
    IdP certificate read from metadata, and identity is extracted."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    assert client.config.want_response_signed is True
    assert client.config.only_idp() == IDP

    session_id, _ = client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    signed = _signed_auth_response(session_id, cert_der_b64, priv)
    raw = base64.b64encode(signed.encode("utf-8")).decode("ascii")
    resp = client.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})
    si = resp.session_info()
    assert si["issuer"] == IDP
    assert si["ava"]["eduPersonPrincipalName"] == ["hubba-bubba@eduid.se"]


def test_signed_response_unsigned_rejected(rsa_keypair, tmp_path):
    """When signatures are required, an unsigned Response is rejected (eduID maps
    this to AssertionError: 'SAML response is not verified')."""
    _priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    session_id, _ = client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    raw = base64.b64encode(_auth_response(session_id).encode("utf-8")).decode("ascii")
    with pytest.raises(AssertionError):
        client.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})


def test_signed_response_tampered_rejected(rsa_keypair, tmp_path):
    """A signed Response whose bytes were altered after signing is rejected."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    session_id, _ = client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    signed = _signed_auth_response(session_id, cert_der_b64, priv)
    tampered = signed.replace("hubba-bubba@eduid.se", "attacker@evil.example")
    raw = base64.b64encode(tampered.encode("utf-8")).decode("ascii")
    with pytest.raises(AssertionError):
        client.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})


def test_metadata_includes_signing_cert(rsa_keypair, tmp_path):
    """When a cert_file is configured, the generated SP metadata embeds it."""
    _priv, cert_pem, _der = rsa_keypair
    cert_file = tmp_path / "sp.crt"
    cert_file.write_bytes(cert_pem)
    conf = {
        "entityid": SP,
        "service": {
            "sp": {"endpoints": {"assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]}}
        },
        "cert_file": str(cert_file),
    }
    xml = entity_descriptor(SPConfig().load(conf)).to_xml()
    assert "<ds:X509Certificate>" in xml
    # parses back and the SP exposes a signing certificate
    ed = md.parse_entity(xml)
    assert ed.signing_certificates("sp")


def test_metadata_unreadable_cert_file_raises():
    """A configured-but-unreadable cert_file fails fast rather than silently
    omitting the certificate from generated metadata."""
    conf = {
        "entityid": SP,
        "service": {
            "sp": {"endpoints": {"assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]}}
        },
        "cert_file": "/nonexistent/path/sp.crt",
    }
    with pytest.raises(ValueError):
        entity_descriptor(SPConfig().load(conf))


# --------------------------------------------------------------------------- #
# Review-fix regression tests (PR #4)
# --------------------------------------------------------------------------- #

def test_parse_tolerates_wrapped_base64(client):
    """A line-wrapped / whitespaced base64 SAMLResponse still decodes (lenient
    base64), rather than failing as if the response were malformed."""
    session_id, _ = client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)
    b64 = base64.b64encode(_auth_response(session_id).encode("utf-8")).decode("ascii")
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64)) + "\n"
    resp = client.parse_authn_request_response(wrapped, BINDING_HTTP_POST, {session_id: "r"})
    assert resp.session_id() == session_id


def test_prepare_uses_requested_binding_endpoint():
    """prepare_for_authenticate honours the requested binding when the IdP
    publishes a distinct SSO endpoint for it."""
    sso_post = "https://idp.example.com/simplesaml/saml2/idp/SSOPost.php"
    conf = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {"assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]},
                "idp": {
                    IDP: {
                        "single_sign_on_service": {
                            BINDING_HTTP_REDIRECT: SSO,
                            BINDING_HTTP_POST: sso_post,
                        }
                    }
                },
            }
        },
    }
    client = Saml2Client(SPConfig().load(conf))
    _sid, info = client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_POST)
    assert info["method"] == "POST"
    assert info["url"] == sso_post  # the POST endpoint, not the Redirect one


def test_prepare_falls_back_to_redirect_endpoint():
    """When the IdP only publishes a Redirect SSO endpoint, a POST request still
    resolves a destination (falls back to the Redirect endpoint)."""
    client = Saml2Client(SPConfig().load(CONF))  # CONF has only a Redirect SSO
    _sid, info = client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_POST)
    assert info["url"] == SSO


def test_decode_normalizes_corrupt_value_to_valueerror():
    """A corrupted pgc1: payload raises a single ValueError, not a low-level
    base64/JSON exception."""
    with pytest.raises(ValueError):
        decode("pgc1:!!!not-base64!!!")
    with pytest.raises(ValueError):
        decode("pgc1:" + base64.urlsafe_b64encode(b"not json").decode("ascii"))


def test_entity_descriptor_requires_entityid():
    """Missing entityid fails fast instead of emitting entityID=''."""
    conf = {
        "service": {
            "sp": {"endpoints": {"assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]}}
        }
    }
    with pytest.raises(ValueError):
        entity_descriptor(SPConfig().load(conf))


def test_cache_set_encodes_payload_name_id():
    """Cache.set encodes the NameID carried in the info payload, not the key
    argument, so a differing payload subject round-trips correctly."""
    from pygamlastan.compat.saml2.cache import Cache

    key_nid = NameID(text="key-subject", format=TRANSIENT, sp_name_qualifier=SP)
    payload_nid = NameID(text="payload-subject", format=TRANSIENT, sp_name_qualifier=SP)
    c = Cache()
    future = int(datetime.now(timezone.utc).timestamp()) + 3600
    c.set(key_nid, IDP, {"ava": {}, "name_id": payload_nid}, not_on_or_after=future)
    info = c.get(key_nid, IDP)
    assert info["name_id"].text == "payload-subject"


def test_global_logout_signed(rsa_keypair, tmp_path):
    """global_logout(sign=True) signs the redirect (passes a sig_alg with the
    signer) instead of erroring on the signer/sig_alg combination."""
    priv, _cert_pem, _der = rsa_keypair
    key_file = tmp_path / "sp.key"
    key_file.write_bytes(priv)
    conf = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(ACS, BINDING_HTTP_POST)],
                    "single_logout_service": [(SLO, BINDING_HTTP_REDIRECT)],
                },
                "idp": {
                    IDP: {"single_logout_service": {BINDING_HTTP_REDIRECT: IDPSLO}}
                },
            }
        },
        "key_file": str(key_file),
    }
    client = Saml2Client(SPConfig().load(conf))
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    logouts = client.global_logout(nid, sign=True)
    location = dict(logouts[IDP][1]["headers"])["Location"]
    params = dict(urllib.parse.parse_qsl(location.split("?", 1)[1]))
    assert "SAMLRequest" in params
    assert "SigAlg" in params and params["SigAlg"]
    assert "Signature" in params


def _client_with_key(rsa_keypair, tmp_path):
    priv, _cert_pem, _der = rsa_keypair
    key_file = tmp_path / "sp.key"
    key_file.write_bytes(priv)
    conf = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {"assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]},
                "idp": {IDP: {"single_sign_on_service": {BINDING_HTTP_REDIRECT: SSO}}},
            }
        },
        "key_file": str(key_file),
    }
    return Saml2Client(SPConfig().load(conf))


def test_prepare_authn_request_signs_redirect_with_key(rsa_keypair, tmp_path):
    """With a key configured, a Redirect AuthnRequest is signed by default."""
    client = _client_with_key(rsa_keypair, tmp_path)
    _sid, info = client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)
    params = dict(urllib.parse.parse_qsl(dict(info["headers"])["Location"].split("?", 1)[1]))
    assert "SAMLRequest" in params
    assert params.get("SigAlg")
    assert "Signature" in params


def test_prepare_authn_request_post_with_key_raises(rsa_keypair, tmp_path):
    """A signing key plus HTTP-POST fails fast: POST request signing is unsupported."""
    client = _client_with_key(rsa_keypair, tmp_path)
    with pytest.raises(ValueError, match="only supported over HTTP-Redirect"):
        client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_POST)


# --------------------------------------------------------------------------- #
# cache.Cache - faithful dict-backed pysaml2 contract
# --------------------------------------------------------------------------- #

def _nid() -> NameID:
    return NameID(text="subject-1", format=TRANSIENT, sp_name_qualifier=SP)


def test_cache_set_get_round_trip():
    from pygamlastan.compat.saml2.cache import Cache

    c = Cache()
    nid = _nid()
    future = int(datetime.now(timezone.utc).timestamp()) + 3600
    c.set(nid, IDP, {"ava": {"mail": ["a@b"]}, "name_id": nid}, not_on_or_after=future)
    info = c.get(nid, IDP)
    assert info["ava"] == {"mail": ["a@b"]}
    # name_id was coded for storage and decoded back to a NameID on get.
    assert isinstance(info["name_id"], NameID)
    assert info["name_id"].text == "subject-1"
    assert c.entities(nid) == [IDP]
    assert c.active(nid, IDP) is True
    assert [s.text for s in c.subjects()] == ["subject-1"]


def test_cache_get_identity_aggregates_and_reports_expired():
    from pygamlastan.compat.saml2.cache import Cache

    c = Cache()
    nid = _nid()
    now = int(datetime.now(timezone.utc).timestamp())
    c.set(nid, IDP, {"ava": {"mail": ["a@b"], "x": ["1"]}}, not_on_or_after=now + 3600)
    c.set(nid, "https://idp2.example/md", {"ava": {"x": ["2"]}}, not_on_or_after=now - 10)
    res, oldees = c.get_identity(nid)
    assert res["mail"] == ["a@b"]
    assert sorted(res["x"]) == ["1"]  # only the still-valid entity contributes
    assert oldees == ["https://idp2.example/md"]


def test_cache_get_expired_raises_too_old():
    from pygamlastan.compat.saml2.cache import Cache, ToOld

    c = Cache()
    nid = _nid()
    past = int(datetime.now(timezone.utc).timestamp()) - 10
    c.set(nid, IDP, {}, not_on_or_after=past)
    with pytest.raises(ToOld):
        c.get(nid, IDP)
    # empty stored info reads back as None (pysaml2 'info or None'), even when
    # the expiry check is skipped
    assert c.get(nid, IDP, check_not_on_or_after=False) is None
    assert c.active(nid, IDP) is False


# --------------------------------------------------------------------------- #
# More review-fix regression tests (binding decode, entityid, SLO discovery)
# --------------------------------------------------------------------------- #

def test_decode_rejects_non_object_json():
    """Valid JSON that is not an object (e.g. a list) normalizes to ValueError."""
    import json

    payload = base64.urlsafe_b64encode(json.dumps([1, 2, 3]).encode()).decode("ascii")
    with pytest.raises(ValueError):
        decode("pgc1:" + payload)


def test_decode_rejects_non_string_field():
    """A NameID field that is valid JSON but not a string normalizes to ValueError."""
    import json

    payload = base64.urlsafe_b64encode(
        json.dumps({"v": ["not", "a", "string"]}).encode()
    ).decode("ascii")
    with pytest.raises(ValueError):
        decode("pgc1:" + payload)


def test_parse_response_redirect_binding(client):
    """A response delivered over HTTP-Redirect (DEFLATE+base64) is inflated and
    parsed, honouring the binding parameter."""
    session_id, _ = client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)
    encoded = deflate_and_base64_encode(_auth_response(session_id))
    resp = client.parse_authn_request_response(encoded, BINDING_HTTP_REDIRECT, {session_id: "r"})
    assert resp.session_id() == session_id


def test_global_logout_sign_without_key_raises():
    """Requesting a signed logout without a configured key fails fast."""
    client = Saml2Client(SPConfig().load(CONF))  # CONF has no key_file
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    with pytest.raises(ValueError):
        client.global_logout(nid, sign=True)


def test_global_logout_blank_nameid_raises(client):
    """A NameID with no identifier text is rejected rather than logging out an empty subject."""
    with pytest.raises(ValueError, match="non-empty identifier"):
        client.global_logout(NameID(text="", format=TRANSIENT))


def _no_entityid_config() -> dict:
    return {
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(ACS, BINDING_HTTP_POST)],
                    "single_logout_service": [(SLO, BINDING_HTTP_REDIRECT)],
                },
                "want_response_signed": False,
                "idp": {
                    IDP: {
                        "single_sign_on_service": {BINDING_HTTP_REDIRECT: SSO},
                        "single_logout_service": {BINDING_HTTP_REDIRECT: IDPSLO},
                    }
                },
            }
        }
    }


def test_prepare_missing_entityid_raises():
    """A missing SP entityid yields a clear ValueError, not a low-level error."""
    client = Saml2Client(SPConfig().load(_no_entityid_config()))
    with pytest.raises(ValueError):
        client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)


def test_parse_missing_entityid_raises():
    """parse_authn_request_response validates the SP entityid up front."""
    full = Saml2Client(SPConfig().load(CONF))
    session_id, _ = full.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)
    raw = base64.b64encode(_auth_response(session_id).encode("utf-8")).decode("ascii")
    client = Saml2Client(SPConfig().load(_no_entityid_config()))
    with pytest.raises(ValueError):
        client.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})


def test_global_logout_missing_entityid_raises():
    """global_logout also validates the SP entityid."""
    client = Saml2Client(SPConfig().load(_no_entityid_config()))
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    with pytest.raises(ValueError):
        client.global_logout(nid)


def test_handle_logout_request_missing_entityid_raises():
    """handle_logout_request raises a clear ValueError when entityid is unset."""
    client = Saml2Client(SPConfig().load(_no_entityid_config()))
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    encoded = deflate_and_base64_encode(_logout_request("id-idp-logout-x"))
    with pytest.raises(ValueError):
        client.handle_logout_request(encoded, nid, BINDING_HTTP_REDIRECT, relay_state="rs")


# --------------------------------------------------------------------------- #
# Round-4 review fixes
# --------------------------------------------------------------------------- #

def _signed_failed_response(req_id: str, cert_b64: str, priv: bytes) -> str:
    unsigned = _failed_response(req_id)
    template = _signature_template("id-resp-fail", cert_b64)
    marker = "</saml:Issuer>"
    idx = unsigned.index(marker) + len(marker)
    spliced = unsigned[:idx] + template + unsigned[idx:]
    return crypto.SamlSigner.from_pem(priv).sign_enveloped(spliced)


def test_signed_failed_status_raises_statuserror(rsa_keypair, tmp_path):
    """A correctly signed but non-Success Response surfaces as StatusError (not
    AssertionError), after signature verification."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    session_id, _ = client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    signed = _signed_failed_response(session_id, cert_der_b64, priv)
    raw = base64.b64encode(signed.encode("utf-8")).decode("ascii")
    with pytest.raises(StatusError):
        client.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})


def test_signed_path_unsigned_failed_is_not_statuserror(rsa_keypair, tmp_path):
    """When signatures are required, an UNSIGNED non-Success Response must fail
    verification (AssertionError) rather than bypass it via the status path."""
    _priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    session_id, _ = client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    raw = base64.b64encode(_failed_response(session_id).encode("utf-8")).decode("ascii")
    with pytest.raises(AssertionError):
        client.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})


def test_global_logout_discovers_metadata_only_idp(tmp_path):
    """global_logout targets an IdP discovered only from metadata (no idp config
    block)."""
    md_path = tmp_path / "idp.xml"
    md_path.write_text(_idp_metadata("dummybase64=="), encoding="utf-8")  # cert unused for SLO
    conf = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(ACS, BINDING_HTTP_POST)],
                    "single_logout_service": [(SLO, BINDING_HTTP_REDIRECT)],
                }
            }
        },
        "metadata": {"local": [str(md_path)]},
    }
    client = Saml2Client(SPConfig().load(conf))
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    logouts = client.global_logout(nid)
    assert IDP in logouts
    assert dict(logouts[IDP][1]["headers"])["Location"].startswith(IDPSLO)


def test_spconfig_reload_clears_metadata(tmp_path):
    """Re-loading an SPConfig replaces metadata instead of accumulating it."""
    md1 = tmp_path / "idp1.xml"
    md1.write_text(_idp_metadata("dummy=="), encoding="utf-8")
    cfg = SPConfig()
    cfg.load({"entityid": SP, "service": {"sp": {}}, "metadata": {"local": [str(md1)]}})
    assert IDP in cfg.metadata
    # second load with no metadata must clear the first
    cfg.load({"entityid": SP, "service": {"sp": {}}})
    assert cfg.metadata == {}


def test_metadata_uses_first_cert_of_chain(rsa_keypair, tmp_path):
    """A full-chain PEM (multiple CERTIFICATE blocks) yields metadata with only
    the first certificate body, not a concatenation of all of them."""
    _priv, cert_pem, cert_der_b64 = rsa_keypair
    chain = tmp_path / "chain.crt"
    # leaf cert followed by a second (here, a copy) - a realistic chain shape.
    chain.write_bytes(cert_pem + b"\n" + cert_pem)
    conf = {
        "entityid": SP,
        "service": {
            "sp": {"endpoints": {"assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]}}
        },
        "cert_file": str(chain),
    }
    xml = entity_descriptor(SPConfig().load(conf)).to_xml()
    assert xml.count("<ds:X509Certificate>") == 1
    # the embedded body equals the single leaf cert's DER base64, and parses back
    assert cert_der_b64 in xml
    assert md.parse_entity(xml).signing_certificates("sp")


def test_cache_zero_timestamp_consistent():
    """A not_on_or_after of 0 is treated as an actual (past) timestamp: get
    raises ToOld and active() reports False, consistently."""
    from pygamlastan.compat.saml2.cache import Cache, ToOld

    c = Cache()
    nid = _nid()
    c.set(nid, IDP, {"ava": {"mail": ["a@b"]}}, not_on_or_after=0)
    with pytest.raises(ToOld):
        c.get(nid, IDP)
    assert c.active(nid, IDP) is False


def test_cache_none_expiry_never_expires():
    """A None not_on_or_after means 'no expiry': get returns info, active True."""
    from pygamlastan.compat.saml2.cache import Cache

    c = Cache()
    nid = _nid()
    c.set(nid, IDP, {"ava": {"mail": ["a@b"]}}, not_on_or_after=None)
    assert c.get(nid, IDP)["ava"] == {"mail": ["a@b"]}
    assert c.active(nid, IDP) is True


def test_cache_unparseable_expiry_fails_closed():
    """An unparseable non-None expiry fails closed: get raises, active False."""
    from pygamlastan.compat.saml2.cache import Cache, ToOld

    c = Cache()
    nid = _nid()
    c.set(nid, IDP, {"ava": {}}, not_on_or_after="not-a-timestamp")
    with pytest.raises(ToOld):
        c.get(nid, IDP)
    assert c.active(nid, IDP) is False


def _two_idp_config() -> dict:
    return {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {"assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]},
                "want_response_signed": False,
                "idp": {
                    IDP: {"single_sign_on_service": {BINDING_HTTP_REDIRECT: SSO}},
                    "https://other.idp.example/md": {
                        "single_sign_on_service": {BINDING_HTTP_REDIRECT: "https://other/sso"}
                    },
                },
            }
        },
    }


def test_parse_ambiguous_idp_requires_explicit_expected():
    """With multiple IdPs, the expected IdP is NOT taken from the unverified
    Response issuer; parse refuses unless given expected_idp explicitly."""
    client = Saml2Client(SPConfig().load(_two_idp_config()))
    raw = base64.b64encode(_auth_response("id-req-x").encode("utf-8")).decode("ascii")
    with pytest.raises(ValueError):
        client.parse_authn_request_response(raw, BINDING_HTTP_POST, {"id-req-x": "r"})


def test_parse_ambiguous_idp_accepts_explicit_expected():
    """Passing expected_idp lets a multi-IdP SP process the response."""
    client = Saml2Client(SPConfig().load(_two_idp_config()))
    raw = base64.b64encode(_auth_response("id-req-x").encode("utf-8")).decode("ascii")
    resp = client.parse_authn_request_response(
        raw, BINDING_HTTP_POST, {"id-req-x": "r"}, expected_idp=IDP
    )
    assert resp.session_info()["issuer"] == IDP


def test_metadata_signing_flags_reflect_config(rsa_keypair, tmp_path):
    """SP metadata advertises AuthnRequestsSigned from key_file and
    WantAssertionsSigned from want_response_signed, instead of hard-coded false."""
    priv, _cert_pem, _der = rsa_keypair
    key_file = tmp_path / "sp.key"
    key_file.write_bytes(priv)
    conf = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {"assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]},
                "want_response_signed": True,
            }
        },
        "key_file": str(key_file),
    }
    xml = entity_descriptor(SPConfig().load(conf)).to_xml()
    assert 'AuthnRequestsSigned="true"' in xml
    assert 'WantAssertionsSigned="true"' in xml

    # Without a key and with signing disabled, both are advertised false.
    conf2 = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {"assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]},
                "want_response_signed": False,
            }
        },
    }
    xml2 = entity_descriptor(SPConfig().load(conf2)).to_xml()
    assert 'AuthnRequestsSigned="false"' in xml2
    assert 'WantAssertionsSigned="false"' in xml2
