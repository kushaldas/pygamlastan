"""Tests for the pysaml2 compatibility shim (``pygamlastan.compat.saml2``).

These mirror the eduID SP flow without the Flask/Mongo stack: build an
AuthnRequest, feed back a Response, read pysaml2-shaped ``session_info``,
round-trip the NameID via ``code``/``decode``, and exercise the Single Logout
helpers and SP metadata generation. Both unsigned (dev) and signed-response
handling are covered here (see the ``test_signed_response_*`` cases); the full
eduID integration is verified separately in the eduid-developer env.
"""

import base64
import html
import itertools
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from pygamlastan import bindings as pgbindings
from pygamlastan import crypto, metadata as md, security
from pygamlastan import xml as pgxml
from pygamlastan.compat import saml2
from pygamlastan.compat.saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from pygamlastan.compat.saml2.client import Saml2Client, _raise_compat_time_error
from pygamlastan.compat.saml2.config import SPConfig
from pygamlastan.compat.saml2.ident import code, decode
from pygamlastan.compat.saml2.metadata import entity_descriptor
from pygamlastan.compat.saml2.response import (
    RequestVersionTooLow,
    StatusError,
    UnsolicitedResponse,
)
from pygamlastan.compat.saml2.s_utils import (
    decode_base64_and_inflate,
    deflate_and_base64_encode,
)
from pygamlastan.compat.saml2.saml import NameID
from pygamlastan.compat.saml2.validate import ResponseLifetimeExceed, ToEarly

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
            # Dev/test config without IdP metadata certs: opt in to the
            # unverified LogoutRequest fallback explicitly (it fails closed
            # without this flag - see the fail-closed test).
            "allow_unsigned_logout_requests": True,
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


# The compat SP's replay cache is deliberately process-scoped (shared across
# Saml2Client instances), so every generated Response/Assertion needs unique
# IDs or later tests would be rejected as replays of earlier ones.
_id_counter = itertools.count(1)


def _fresh_ids() -> tuple[str, str]:
    n = next(_id_counter)
    return f"id-resp-{n}", f"id-assert-{n}"


def _auth_response(req_id: str, resp_id: str | None = None, assert_id: str | None = None) -> str:
    if resp_id is None or assert_id is None:
        fresh_resp, fresh_assert = _fresh_ids()
        resp_id = resp_id or fresh_resp
        assert_id = assert_id or fresh_assert
    now = datetime.now(timezone.utc)
    ts = (now - timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    tomorrow = (now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"""<?xml version='1.0' encoding='UTF-8'?>
<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{ACS}" ID="{resp_id}" InResponseTo="{req_id}" IssueInstant="{ts}" Version="2.0">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{IDP}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="{assert_id}" IssueInstant="{ts}" Version="2.0">
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


def _signed_logout_response(req_id: str, cert_b64: str, private_key: bytes) -> str:
    """A LogoutResponse with an enveloped signature over its root element."""
    unsigned = _logout_response(req_id)
    template = _signature_template("id-lr-1", cert_b64)
    issuer_end = unsigned.index("</saml:Issuer>") + len("</saml:Issuer>")
    templated = unsigned[:issuer_end] + template + unsigned[issuer_end:]
    return crypto.SamlSigner.from_pem(private_key).sign_enveloped(templated)


def _redirect_signed_logout_response(
    req_id: str, private_key: bytes, relay_state: str | None = None
) -> tuple[str, str, str, str]:
    """Build the exact detached-signature inputs for a Redirect response."""
    signer = crypto.SamlSigner.from_pem(private_key)
    sig_alg = signer.signature_method_uri()
    encoded = deflate_and_base64_encode(_logout_response(req_id))
    parts = ["SAMLResponse=" + urllib.parse.quote(encoded, safe="")]
    if relay_state is not None:
        parts.append("RelayState=" + urllib.parse.quote(relay_state, safe=""))
    parts.append("SigAlg=" + urllib.parse.quote(sig_alg, safe=""))
    signed_query = "&".join(parts)
    signature = signer.sign_redirect_query(signed_query.encode("utf-8"), sig_alg)
    return (
        encoded,
        sig_alg,
        base64.b64encode(signature).decode("ascii"),
        signed_query,
    )


def _logout_request(
    req_id: str,
    issuer: str = IDP,
    issue_instant: str | None = None,
    destination: str | None = SLO,
) -> str:
    ts = issue_instant or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    destination_attr = f' Destination="{destination}"' if destination is not None else ""
    return f"""<?xml version='1.0' encoding='UTF-8'?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{req_id}" IssueInstant="{ts}" Version="2.0"{destination_attr}>
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:NameID Format="{TRANSIENT}" SPNameQualifier="{SP}">abc123hash</saml:NameID>
  <samlp:SessionIndex>session-1</samlp:SessionIndex>
</samlp:LogoutRequest>"""


def _failed_response(
    req_id: str, resp_id: str | None = None, sub_status: str | None = None
) -> str:
    if resp_id is None:
        resp_id = "fail-" + _fresh_ids()[0]
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nested = (
        f'<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:{sub_status}"/>'
        if sub_status
        else ""
    )
    return f"""<?xml version='1.0' encoding='UTF-8'?>
<samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="{ACS}" ID="{resp_id}" InResponseTo="{req_id}" IssueInstant="{ts}" Version="2.0">
  <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{IDP}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">{nested}</samlp:StatusCode></samlp:Status>
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
    resp_id, assert_id = _fresh_ids()
    unsigned = _auth_response(req_id, resp_id=resp_id, assert_id=assert_id)
    template = _signature_template(resp_id, cert_b64)
    marker = "</saml:Issuer>"  # the Response's Issuer is the first in the doc
    idx = unsigned.index(marker) + len(marker)
    spliced = unsigned[:idx] + template + unsigned[idx:]
    return crypto.SamlSigner.from_pem(priv).sign_enveloped(spliced)


def _assertion_signed_auth_response(req_id: str, cert_b64: str, priv: bytes) -> str:
    """The test AuthnResponse with only its Assertion directly signed."""
    resp_id, assertion_id = _fresh_ids()
    unsigned = _auth_response(req_id, resp_id=resp_id, assert_id=assertion_id)
    template = _signature_template(assertion_id, cert_b64)
    assertion_start = unsigned.index("<saml:Assertion")
    issuer_end = unsigned.index("</saml:Issuer>", assertion_start) + len(
        "</saml:Issuer>"
    )
    templated = unsigned[:issuer_end] + template + unsigned[issuer_end:]
    return crypto.SamlSigner.from_pem(priv).sign_enveloped(templated)


def _idp_metadata(*cert_der_b64s: str) -> str:
    """IdP metadata publishing one signing KeyDescriptor per certificate (key
    rollover publishes several simultaneously)."""
    key_descriptors = "".join(
        f"""<md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>"""
        for cert in cert_der_b64s
    )
    return f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    {key_descriptors}
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


def test_djangosaml2_import_surface_is_present():
    """Every pysaml2 symbol imported by djangosaml2 resolves from the shim."""
    from pygamlastan.compat.saml2.client_base import LogoutError
    from pygamlastan.compat.saml2.mdstore import MetaDataMDX, SourceNotFound
    from pygamlastan.compat.saml2.response import (
        RequestVersionTooLow,
        SignatureError,
        StatusAuthnFailed,
        StatusNoAuthnContext,
        StatusRequestDenied,
    )
    from pygamlastan.compat.saml2.s_utils import UnknownSystemEntity, UnsupportedBinding
    from pygamlastan.compat.saml2.sigver import MissingKey
    from pygamlastan.compat.saml2.validate import ResponseLifetimeExceed, ToEarly

    assert saml2.saml.NAMESPACE.endswith(":assertion")
    assert saml2.samlp.NAMESPACE.endswith(":protocol")
    assert saml2.md.NAMESPACE.endswith(":metadata")
    assert saml2.xmldsig.SIG_RSA_SHA256.endswith("rsa-sha256")
    assert saml2.xmlenc.NAMESPACE.endswith("xmlenc#")
    for exception in (
        LogoutError,
        SourceNotFound,
        RequestVersionTooLow,
        SignatureError,
        StatusAuthnFailed,
        StatusNoAuthnContext,
        StatusRequestDenied,
        UnknownSystemEntity,
        UnsupportedBinding,
        MissingKey,
        ResponseLifetimeExceed,
        ToEarly,
    ):
        assert issubclass(exception, Exception)
    assert isinstance(MetaDataMDX(), MetaDataMDX)


def test_public_saml_failures_share_samlerror_base():
    """Generic pysaml2 error handlers catch the shim's SAML failures."""
    from pygamlastan.compat.saml2.cache import ToOld
    from pygamlastan.compat.saml2.client_base import LogoutError
    from pygamlastan.compat.saml2.response import SignatureError
    from pygamlastan.compat.saml2.s_utils import UnknownSystemEntity
    from pygamlastan.compat.saml2.sigver import MissingKey

    for exception in (
        LogoutError,
        MissingKey,
        RequestVersionTooLow,
        SignatureError,
        StatusError,
        ToOld,
        UnsolicitedResponse,
        UnknownSystemEntity,
        ResponseLifetimeExceed,
        ToEarly,
    ):
        assert issubclass(exception, saml2.SAMLError)

    assert issubclass(SignatureError, AssertionError)


def test_spconfig_load_and_only_idp():
    cfg = SPConfig().load(CONF)
    assert cfg.entityid == SP
    assert cfg.only_idp() == IDP
    assert cfg.single_sign_on_service(IDP, BINDING_HTTP_REDIRECT) == SSO
    assert cfg.single_logout_service(IDP, BINDING_HTTP_REDIRECT) == IDPSLO
    assert cfg.want_response_signed is False
    assert cfg.want_logout_response_signed is False
    assert cfg.accepted_time_diff == 0


def test_spconfig_loads_accepted_time_diff():
    cfg = SPConfig().load({**CONF, "accepted_time_diff": 60})
    assert cfg.accepted_time_diff == 60


def test_spconfig_keeps_name_id_capabilities_and_policy_separate():
    """Advertised NameID formats do not become a request policy."""
    formats = [TRANSIENT, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"]
    sp = {
        **CONF["service"]["sp"],
        "name_id_format": formats,
        "name_id_policy_format": TRANSIENT,
    }

    cfg = SPConfig().load({**CONF, "service": {"sp": sp}})

    assert cfg.name_id_format == formats
    assert cfg.name_id_policy_format == TRANSIENT


def test_scalar_name_id_capability_does_not_create_request_policy():
    """A scalar metadata capability is not reused as NameIDPolicy format."""
    sp = {**CONF["service"]["sp"], "name_id_format": TRANSIENT}
    configured_client = Saml2Client(
        SPConfig().load({**CONF, "service": {"sp": sp}})
    )

    _request_id, xml = configured_client.create_authn_request(SSO)

    assert pgxml.parse_authn_request(xml).name_id_policy is None


def test_spconfig_normalizes_string_boolean_options():
    """Textual config booleans preserve their intended truth values."""
    sp = {
        **CONF["service"]["sp"],
        "want_response_signed": "false",
        "want_assertions_signed": " TRUE ",
        "want_logout_response_signed": "false",
        "authn_requests_signed": "true",
        "logout_requests_signed": "0",
        "logout_responses_signed": "1",
        "force_authn": "no",
        "allow_create": "yes",
        "allow_unsigned_logout_requests": "off",
    }

    cfg = SPConfig().load({**CONF, "service": {"sp": sp}})

    assert cfg.want_response_signed is False
    assert cfg.want_assertions_signed is True
    assert cfg.want_logout_response_signed is False
    assert cfg.authn_requests_signed is True
    assert cfg.logout_requests_signed is False
    assert cfg.logout_responses_signed is True
    assert cfg.force_authn is False
    assert cfg.allow_create is True
    assert cfg.allow_unsigned_logout_requests is False


def test_metadata_store_has_djangosaml2_query_shape(tmp_path):
    """Loaded metadata supports djangosaml2's name/service/store navigation."""
    path = tmp_path / "idp.xml"
    path.write_text(_idp_metadata(), encoding="utf-8")
    cfg = SPConfig().load(
        {
            "entityid": SP,
            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]
                    }
                }
            },
            "metadata": {"local": [str(path)]},
        }
    )
    assert str(path) in cfg.metadata.metadata
    assert cfg.metadata.name(IDP) == IDP
    services = cfg.metadata.service(
        IDP, "idpsso_descriptor", "single_sign_on_service"
    )
    assert services[BINDING_HTTP_REDIRECT][0]["location"] == SSO
    logout_services = cfg.metadata.single_logout_service(
        IDP, binding=BINDING_HTTP_REDIRECT, typ="idpsso"
    )
    assert isinstance(logout_services, list)
    assert logout_services[0]["binding"] == BINDING_HTTP_REDIRECT
    assert logout_services[0]["location"] == IDPSLO
    assert cfg.metadata.service(
        IDP,
        "idpsso_descriptor",
        "single_logout_service",
        BINDING_HTTP_POST,
    ) == []
    assert IDP in cfg.metadata.with_descriptor("idpsso")


def test_missing_metadata_file_raises_source_not_found(tmp_path):
    """Configuration exposes pysaml2's metadata-source exception contract."""
    from pygamlastan.compat.saml2.mdstore import SourceNotFound

    missing = tmp_path / "missing.xml"
    with pytest.raises(SourceNotFound, match="missing.xml"):
        SPConfig().load({"metadata": {"local": [str(missing)]}})


def test_logout_security_options_are_independent_and_explicit():
    """AuthnResponse policy does not implicitly weaken or strengthen SLO."""
    conf = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]
                },
                "want_response_signed": False,
            }
        },
    }
    cfg = SPConfig().load(conf)
    assert cfg.want_logout_response_signed is False
    assert cfg.allow_unsigned_logout_requests is False


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
    assert isinstance(si["not_on_or_after"], int)
    assert si["not_on_or_after"] > datetime.now(timezone.utc).timestamp()
    assert si["authn_info"][0][0] == PPT
    datetime.fromisoformat(si["authn_info"][0][2])  # authn instant is parseable
    assert isinstance(si["name_id"], NameID)
    assert si["name_id"].text == "abc123hash"
    assert si["name_id"].format == TRANSIENT

    # djangosaml2 checks bearer confirmation expiry through this pysaml2
    # object graph before completing authentication.
    confirmations = resp.assertion.subject.subject_confirmation
    assert confirmations[0].method == saml2.saml.SCM_BEARER
    confirmation_expiry = confirmations[0].subject_confirmation_data.not_on_or_after
    assert isinstance(confirmation_expiry, str)
    assert datetime.fromisoformat(confirmation_expiry).tzinfo is not None


def test_identity_cache_uses_conditions_expiry_without_session_expiry():
    """A finite assertion lifetime bounds cached sessions when AuthnStatement
    omits SessionNotOnOrAfter."""
    from pygamlastan.compat.saml2.cache import Cache

    identity_cache = Cache()
    cached_client = Saml2Client(
        SPConfig().load(CONF), identity_cache=identity_cache
    )
    session_id, _ = cached_client.prepare_for_authenticate(
        entityid=IDP, binding=BINDING_HTTP_REDIRECT
    )
    raw = base64.b64encode(_auth_response(session_id).encode("utf-8")).decode(
        "ascii"
    )

    response = cached_client.parse_authn_request_response(
        raw, BINDING_HTTP_POST, {session_id: "ref-1"}
    )
    info = response.session_info()
    cached = identity_cache._db[code(info["name_id"])][IDP]

    assert cached[0] == info["not_on_or_after"]
    assert cached[0] is not None


def test_response_adapter_uses_the_processed_authn_assertion(monkeypatch, client):
    """The djangosaml2-facing assertion matches the one selected natively."""
    session_id, _ = client.prepare_for_authenticate(
        entityid=IDP, binding=BINDING_HTTP_REDIRECT
    )
    authenticated_id = "id-authenticated-assertion"
    xml = _auth_response(session_id, assert_id=authenticated_id)
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    attribute_only = f"""<saml:Assertion ID="id-attribute-only" IssueInstant="{issue_instant}" Version="2.0">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">{IDP}</saml:Issuer>
    <saml:AttributeStatement>
      <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml:AttributeValue>attribute-only@example.org</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  """
    xml = xml.replace("  <saml:Assertion ", f"  {attribute_only}<saml:Assertion ", 1)
    raw = base64.b64encode(xml.encode("utf-8")).decode("ascii")
    result = SimpleNamespace(assertion_id=authenticated_id)
    monkeypatch.setattr(
        "pygamlastan.compat.saml2.client._profiles.process_response",
        lambda *args, **kwargs: result,
    )

    response = client.parse_authn_request_response(
        raw, BINDING_HTTP_POST, {session_id: "ref-1"}
    )

    assert response.assertion.id == authenticated_id
    assert response.assertion.subject is not None


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


def test_do_logout_falls_back_when_expected_binding_is_unavailable(client):
    """djangosaml2's preferred binding does not exclude published fallbacks."""
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)

    binding, info = client.do_logout(
        nid,
        [IDP],
        "",
        None,
        expected_binding=BINDING_HTTP_POST,
    )[IDP]

    assert binding == BINDING_HTTP_REDIRECT
    assert dict(info["headers"])["Location"].startswith(IDPSLO)


def test_do_logout_rejects_partial_multi_idp_results():
    """Every requested IdP must resolve before any logout state is created."""
    from pygamlastan.compat.saml2.client_base import LogoutError

    state: dict[str, dict[str, str]] = {}
    logout_client = Saml2Client(SPConfig().load(CONF), state_cache=state)
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    missing_idp = "https://idp-without-slo.example.org"

    with pytest.raises(LogoutError, match=missing_idp):
        logout_client.do_logout(nid, [IDP, missing_idp], "", None)

    assert state == {}


def test_global_logout_carries_reason_and_expiry(client):
    """The lower-level request preserves pysaml2's reason/expire arguments."""
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    _binding, info = client.global_logout(
        nid, reason="urn:example:logout", expire=expiry
    )[IDP]
    query = dict(info["headers"])["Location"].split("?", 1)[1]
    request = pgxml.parse_logout_request(
        pgbindings.redirect_decode(query).saml_text
    )
    assert request.reason == "urn:example:logout"
    assert request.not_on_or_after == expiry.replace(microsecond=0)


def test_global_logout_rejects_expired_deadline(client):
    """An already-expired logout operation does not contact federation peers."""
    from pygamlastan.compat.saml2.client_base import LogoutError

    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    with pytest.raises(LogoutError, match="already passed"):
        client.global_logout(nid, expire=datetime.now(timezone.utc) - timedelta(seconds=1))


def test_global_logout_persists_and_consumes_correlation_state():
    """djangosaml2's session state adapter correlates a real LogoutResponse."""
    state: dict[str, dict[str, str]] = {}
    client = Saml2Client(SPConfig().load(CONF), state_cache=state)
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    binding, info = client.global_logout(nid)[IDP]
    assert binding == BINDING_HTTP_REDIRECT
    query = dict(info["headers"])["Location"].split("?", 1)[1]
    request = pgbindings.redirect_decode(query)
    request_id = pgxml.parse_logout_request(request.saml_text).id
    assert state[request_id]["entity_id"] == IDP

    encoded = deflate_and_base64_encode(_logout_response(request_id))
    response = client.parse_logout_request_response(encoded, BINDING_HTTP_REDIRECT)
    assert response.status_ok()
    assert request_id not in state


def test_create_authn_request_adapts_djangosaml2_scoping(client):
    """Mutable pysaml2 scoping objects reach the typed native request builder."""
    scoping = saml2.samlp.Scoping(
        proxy_count=1,
        idp_list=saml2.samlp.IDPList(
            idp_entry=[saml2.samlp.IDPEntry(provider_id=IDP)]
        ),
    )
    request_id, xml = client.create_authn_request(SSO, scoping=scoping)
    request = pgxml.parse_authn_request(xml)
    assert request.id == request_id
    assert request.scoping.proxy_count == 1
    assert request.scoping.idp_list == [IDP]


def test_parse_logout_request_response_status_ok(client):
    encoded = deflate_and_base64_encode(_logout_response("req-1"))
    resp = client.parse_logout_request_response(encoded, BINDING_HTTP_REDIRECT)
    assert resp.status_ok() is True


def test_signed_logout_response_is_verified_and_correlated(rsa_keypair, tmp_path):
    """want_logout_response_signed verifies the exact correlated response."""
    private_key, _cert_pem, cert_der_b64 = rsa_keypair
    base = _signed_client(tmp_path, cert_der_b64)
    base.config.want_logout_response_signed = True
    state: dict[str, dict[str, str]] = {}
    client = Saml2Client(base.config, state_cache=state)
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    _binding, info = client.global_logout(nid)[IDP]
    query = dict(info["headers"])["Location"].split("?", 1)[1]
    request_id = pgxml.parse_logout_request(
        pgbindings.redirect_decode(query).saml_text
    ).id
    xml = _signed_logout_response(request_id, cert_der_b64, private_key)
    encoded = deflate_and_base64_encode(xml)
    assert client.parse_logout_request_response(encoded).status_ok()
    assert request_id not in state


def test_signed_logout_response_policy_rejects_unsigned(rsa_keypair, tmp_path):
    """Unsigned responses become StatusError without consuming SLO state."""
    _private_key, _cert_pem, cert_der_b64 = rsa_keypair
    base = _signed_client(tmp_path, cert_der_b64)
    base.config.want_logout_response_signed = True
    state = {"request-id": {"entity_id": IDP}}
    client = Saml2Client(base.config, state_cache=state)
    encoded = deflate_and_base64_encode(_logout_response("request-id"))
    with pytest.raises(StatusError, match="signature verification failed"):
        client.parse_logout_request_response(encoded)
    assert "request-id" in state


def test_detached_redirect_logout_response_is_verified(rsa_keypair, tmp_path):
    """A valid exact Redirect query authenticates and consumes correlation state."""
    private_key, _cert_pem, cert_der_b64 = rsa_keypair
    base = _signed_client(tmp_path, cert_der_b64)
    base.config.want_logout_response_signed = True
    state = {"redirect-response": {"entity_id": IDP}}
    signed_client = Saml2Client(base.config, state_cache=state)
    encoded, sig_alg, signature, signed_query = _redirect_signed_logout_response(
        "redirect-response", private_key, relay_state="relay value"
    )

    response = signed_client.parse_logout_request_response(
        encoded,
        BINDING_HTTP_REDIRECT,
        sig_alg=sig_alg,
        signature=signature,
        signed_query=signed_query,
    )

    assert response.status_ok()
    assert "redirect-response" not in state


def test_tampered_redirect_logout_response_retains_state(rsa_keypair, tmp_path):
    """A tampered detached signature becomes StatusError and preserves state."""
    private_key, _cert_pem, cert_der_b64 = rsa_keypair
    base = _signed_client(tmp_path, cert_der_b64)
    base.config.want_logout_response_signed = True
    state = {"tampered-response": {"entity_id": IDP}}
    signed_client = Saml2Client(base.config, state_cache=state)
    encoded, sig_alg, signature, signed_query = _redirect_signed_logout_response(
        "tampered-response", private_key
    )
    tampered = bytearray(base64.b64decode(signature))
    tampered[0] ^= 1

    with pytest.raises(StatusError, match="signature verification failed"):
        signed_client.parse_logout_request_response(
            encoded,
            BINDING_HTTP_REDIRECT,
            sig_alg=sig_alg,
            signature=base64.b64encode(tampered).decode("ascii"),
            signed_query=signed_query,
        )

    assert "tampered-response" in state


def test_incomplete_redirect_logout_signature_retains_state(rsa_keypair, tmp_path):
    """A partial detached-signature tuple fails without consuming state."""
    private_key, _cert_pem, cert_der_b64 = rsa_keypair
    base = _signed_client(tmp_path, cert_der_b64)
    base.config.want_logout_response_signed = True
    state = {"incomplete-response": {"entity_id": IDP}}
    signed_client = Saml2Client(base.config, state_cache=state)
    encoded, sig_alg, _signature, signed_query = _redirect_signed_logout_response(
        "incomplete-response", private_key
    )

    with pytest.raises(StatusError, match="all required"):
        signed_client.parse_logout_request_response(
            encoded,
            BINDING_HTTP_REDIRECT,
            sig_alg=sig_alg,
            signed_query=signed_query,
        )

    assert "incomplete-response" in state


def test_logout_response_missing_key_is_statuserror(client):
    """A missing response verification key is compatible with LogoutView."""
    client.config.want_logout_response_signed = True
    client.state_cache = client.state = {
        "missing-key-response": {"entity_id": IDP}
    }
    encoded = deflate_and_base64_encode(_logout_response("missing-key-response"))

    with pytest.raises(StatusError, match="signature verification failed"):
        client.parse_logout_request_response(encoded)

    assert "missing-key-response" in client.state


def test_consumed_logout_response_is_statuserror(client):
    """A stale correlation failure follows djangosaml2's handled error path."""
    client.state_cache = client.state = {}
    encoded = deflate_and_base64_encode(_logout_response("already-consumed"))

    with pytest.raises(StatusError, match="not outstanding"):
        client.parse_logout_request_response(encoded)


def test_handle_logout_request_redirects_to_idp(client):
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)
    encoded = deflate_and_base64_encode(_logout_request("id-idp-logout-1"))
    info = client.handle_logout_request(encoded, nid, BINDING_HTTP_REDIRECT, relay_state="rs")
    assert info["headers"][0][1].startswith(IDPSLO + "?SAMLResponse=")


def test_logout_response_prefers_metadata_response_location(tmp_path):
    """Responses use ResponseLocation while requests continue using Location."""
    response_location = IDPSLO + "/responses"
    metadata_file = tmp_path / "idp-response-location.xml"
    metadata_file.write_text(
        _idp_metadata().replace(
            f'Location="{IDPSLO}"',
            f'Location="{IDPSLO}" ResponseLocation="{response_location}"',
            1,
        ),
        encoding="utf-8",
    )
    conf = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(ACS, BINDING_HTTP_POST)],
                    "single_logout_service": [(SLO, BINDING_HTTP_REDIRECT)],
                },
                "allow_unsigned_logout_requests": True,
            }
        },
        "metadata": {"local": [str(metadata_file)]},
    }
    response_client = Saml2Client(SPConfig().load(conf))
    nid = NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)

    _binding, request_info = response_client.global_logout(nid)[IDP]
    assert dict(request_info["headers"])["Location"].startswith(IDPSLO)
    encoded = deflate_and_base64_encode(
        _logout_request("id-response-location")
    )
    response_info = response_client.handle_logout_request(
        encoded, nid, BINDING_HTTP_REDIRECT
    )

    location = dict(response_info["headers"])["Location"]
    assert location.startswith(response_location + "?SAMLResponse=")
    response_xml = pgbindings.redirect_decode(
        urllib.parse.urlsplit(location).query
    ).saml_text
    assert f'Destination="{response_location}"' in response_xml


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


def test_empty_requested_authn_context_overrides_configured_context():
    """An explicit empty mapping disables the configured request context."""
    conf = {
        **CONF,
        "service": {
            "sp": {
                **CONF["service"]["sp"],
                "requested_authn_context": {
                    "authn_context_class_ref": [PPT],
                    "comparison": "exact",
                },
            }
        },
    }
    configured_client = Saml2Client(SPConfig().load(conf))

    _request_id, xml = configured_client.create_authn_request(
        SSO, requested_authn_context={}
    )

    assert pgxml.parse_authn_request(xml).requested_authn_context is None


def test_create_authn_request_separates_response_and_acs_bindings():
    """ProtocolBinding remains independent from the ACS lookup binding."""
    redirect_acs = ACS + "/redirect"
    sp = {
        **CONF["service"]["sp"],
        "endpoints": {
            **CONF["service"]["sp"]["endpoints"],
            "assertion_consumer_service": [
                (ACS, BINDING_HTTP_POST),
                (redirect_acs, BINDING_HTTP_REDIRECT),
            ],
        },
    }
    binding_client = Saml2Client(
        SPConfig().load({**CONF, "service": {"sp": sp}})
    )

    _request_id, xml = binding_client.create_authn_request(
        SSO,
        binding=BINDING_HTTP_POST,
        service_url_binding=BINDING_HTTP_REDIRECT,
    )
    request = pgxml.parse_authn_request(xml)

    assert request.protocol_binding == BINDING_HTTP_POST
    assert request.assertion_consumer_service_url == redirect_acs


def test_transient_authn_request_omits_allow_create():
    """Transient NameIDPolicy never serializes the prohibited AllowCreate."""
    sp = {
        **CONF["service"]["sp"],
        "name_id_policy_format": TRANSIENT,
        "allow_create": True,
    }
    configured_client = Saml2Client(
        SPConfig().load({**CONF, "service": {"sp": sp}})
    )

    _request_id, xml = configured_client.create_authn_request(SSO)

    policy = pgxml.parse_authn_request(xml).name_id_policy
    assert policy.format == TRANSIENT
    assert "AllowCreate" not in xml


def test_prepare_honors_response_binding_separately_from_acs_lookup():
    """prepare_for_authenticate forwards both pysaml2 binding options."""
    redirect_acs = ACS + "/redirect"
    sp = {
        **CONF["service"]["sp"],
        "endpoints": {
            **CONF["service"]["sp"]["endpoints"],
            "assertion_consumer_service": [
                (ACS, BINDING_HTTP_POST),
                (redirect_acs, BINDING_HTTP_REDIRECT),
            ],
        },
    }
    binding_client = Saml2Client(
        SPConfig().load({**CONF, "service": {"sp": sp}})
    )

    _request_id, info = binding_client.prepare_for_authenticate(
        entityid=IDP,
        binding=BINDING_HTTP_REDIRECT,
        response_binding=BINDING_HTTP_POST,
        service_url_binding=BINDING_HTTP_REDIRECT,
    )
    query = dict(info["headers"])["Location"].split("?", 1)[1]
    request = pgxml.parse_authn_request(
        pgbindings.redirect_decode(query).saml_text
    )

    assert request.protocol_binding == BINDING_HTTP_POST
    assert request.assertion_consumer_service_url == redirect_acs


def test_prepare_post_binding():
    """A published POST SSO endpoint produces an auto-submitting POST form."""
    sp = {
        **CONF["service"]["sp"],
        "idp": {
            IDP: {
                **CONF["service"]["sp"]["idp"][IDP],
                "single_sign_on_service": {
                    BINDING_HTTP_REDIRECT: SSO,
                    BINDING_HTTP_POST: SSO,
                },
            }
        },
    }
    post_client = Saml2Client(
        SPConfig().load({**CONF, "service": {"sp": sp}})
    )

    _session_id, info = post_client.prepare_for_authenticate(
        entityid=IDP, binding=BINDING_HTTP_POST
    )
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


def test_prepare_uses_pysaml2_compatible_request_id(client):
    """The request ID remains readable by djangosaml2's legacy extractor."""
    session_id, _info = client.prepare_for_authenticate(
        entityid=IDP, binding=BINDING_HTTP_REDIRECT
    )
    assert re.fullmatch(r"[a-z0-9-]+", session_id, re.I)


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


@pytest.mark.parametrize(
    "sub_status,exception_name",
    [
        ("AuthnFailed", "StatusAuthnFailed"),
        ("NoAuthnContext", "StatusNoAuthnContext"),
        ("RequestDenied", "StatusRequestDenied"),
    ],
)
def test_nested_failure_status_uses_specific_exception(
    client, sub_status, exception_name
):
    """djangosaml2 receives the specific exception from a nested status code."""
    from pygamlastan.compat.saml2 import response as response_module

    session_id, _ = client.prepare_for_authenticate(
        entityid=IDP, binding=BINDING_HTTP_REDIRECT
    )
    raw = base64.b64encode(
        _failed_response(session_id, sub_status=sub_status).encode()
    ).decode()
    exception = getattr(response_module, exception_name)
    with pytest.raises(exception):
        client.parse_authn_request_response(
            raw, BINDING_HTTP_POST, {session_id: "return"}
        )


def test_decode_accepts_legacy_pysaml2_string():
    """Existing pysaml2 sessions remain readable during a rolling upgrade."""
    value = decode("0=idp.example,2=urn:something,4=legacy-subject")
    assert value.text == "legacy-subject"
    assert value.name_qualifier == "idp.example"
    assert value.format == "urn:something"


def test_decode_accepts_bare_subject_string():
    """djangosaml2 historically persisted just ``NameID.text`` in sessions."""
    assert decode("legacy-subject").text == "legacy-subject"


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


def test_legacy_nil_attribute_text_is_recovered(client):
    """Legacy nil text is recovered through the strict wire-name converter."""
    session_id, _ = client.prepare_for_authenticate(
        entityid=IDP, binding=BINDING_HTTP_REDIRECT
    )
    xml = _auth_response(session_id).replace(
        'FriendlyName="eduPersonPrincipalName"',
        'FriendlyName="isAdmin"',
        1,
    ).replace(
        "<saml:AttributeValue>hubba-bubba@eduid.se</saml:AttributeValue>",
        '<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xsi:nil="true">hubba-bubba@eduid.se</saml:AttributeValue>',
    )
    raw = base64.b64encode(xml.encode()).decode()
    response = client.parse_authn_request_response(
        raw, BINDING_HTTP_POST, {session_id: "return"}
    )
    assert response.ava["eduPersonPrincipalName"] == ["hubba-bubba@eduid.se"]
    assert "isAdmin" not in response.ava


def test_legacy_nil_unknown_wire_attribute_is_rejected(client):
    """A malicious FriendlyName cannot introduce an unmapped local attribute."""
    session_id, _ = client.prepare_for_authenticate(
        entityid=IDP, binding=BINDING_HTTP_REDIRECT
    )
    xml = _auth_response(session_id).replace(
        'Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" '
        'FriendlyName="eduPersonPrincipalName"',
        'Name="urn:example:unknown-admin" FriendlyName="isAdmin"',
        1,
    ).replace(
        "<saml:AttributeValue>hubba-bubba@eduid.se</saml:AttributeValue>",
        '<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xsi:nil="true">true</saml:AttributeValue>',
        1,
    )
    raw = base64.b64encode(xml.encode()).decode()

    response = client.parse_authn_request_response(
        raw, BINDING_HTTP_POST, {session_id: "return"}
    )

    assert "isAdmin" not in response.ava
    assert "urn:example:unknown-admin" not in response.ava


# --------------------------------------------------------------------------- #
# Signed-response path (what real eduID deployments use)
# --------------------------------------------------------------------------- #

def _signed_client(tmp_path, *cert_der_b64s):
    md_path = tmp_path / "idp_metadata.xml"
    md_path.write_text(_idp_metadata(*cert_der_b64s), encoding="utf-8")
    conf = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(ACS, BINDING_HTTP_POST)],
                    "single_logout_service": [
                        (SLO, BINDING_HTTP_REDIRECT),
                        (SLO, BINDING_HTTP_POST),
                    ],
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


def test_deprecated_response_version_raises_compat_exception(client):
    session_id, _ = client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    xml = _auth_response(session_id).replace('Version="2.0"', 'Version="1.1"', 1)
    raw = base64.b64encode(xml.encode()).decode()

    with pytest.raises(RequestVersionTooLow):
        client.parse_authn_request_response(
            raw, BINDING_HTTP_POST, {session_id: "return"}
        )


def test_expired_assertion_raises_compat_lifetime_exception(client):
    session_id, _ = client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    expired = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    xml = re.sub(
        r'NotOnOrAfter="[^"]+"',
        f'NotOnOrAfter="{expired}"',
        _auth_response(session_id),
    )
    raw = base64.b64encode(xml.encode()).decode()

    with pytest.raises(ResponseLifetimeExceed):
        client.parse_authn_request_response(
            raw, BINDING_HTTP_POST, {session_id: "return"}
        )


def test_assertion_age_classifier_includes_clock_skew():
    """Compatibility expiry classification matches native skew handling."""
    cfg = security.SecurityConfig()
    cfg.max_assertion_age_seconds = 300
    cfg.clock_skew_seconds = 60
    within_skew = (datetime.now(timezone.utc) - timedelta(seconds=330)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    xml = re.sub(
        r'(<saml:Assertion[^>]*IssueInstant=")[^"]+',
        rf"\g<1>{within_skew}",
        _auth_response("id-skew-grace"),
        count=1,
    )

    _raise_compat_time_error(pgxml.parse_response(xml), cfg)

    outside_skew = (datetime.now(timezone.utc) - timedelta(seconds=370)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    xml = re.sub(
        r'(<saml:Assertion[^>]*IssueInstant=")[^"]+',
        rf"\g<1>{outside_skew}",
        xml,
        count=1,
    )
    with pytest.raises(ResponseLifetimeExceed):
        _raise_compat_time_error(pgxml.parse_response(xml), cfg)


def test_future_assertion_raises_compat_too_early_exception(client):
    session_id, _ = client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    xml = re.sub(
        r'(<saml:Conditions )NotBefore="[^"]+"',
        rf'\1NotBefore="{future}"',
        _auth_response(session_id),
    )
    raw = base64.b64encode(xml.encode()).decode()

    with pytest.raises(ToEarly):
        client.parse_authn_request_response(
            raw, BINDING_HTTP_POST, {session_id: "return"}
        )


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


def _assertion_signed_client(tmp_path, cert_der_b64: str) -> Saml2Client:
    path = tmp_path / "assertion-signing-idp.xml"
    path.write_text(_idp_metadata(cert_der_b64), encoding="utf-8")
    conf = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]
                },
                "want_response_signed": False,
                "want_assertions_signed": True,
            }
        },
        "metadata": {"local": [str(path)]},
    }
    return Saml2Client(SPConfig().load(conf))


def test_direct_assertion_signature_policy_accepted(rsa_keypair, tmp_path):
    """want_assertions_signed accepts an Assertion-signed response envelope."""
    private_key, _cert_pem, cert_der_b64 = rsa_keypair
    client = _assertion_signed_client(tmp_path, cert_der_b64)
    session_id, _ = client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    xml = _assertion_signed_auth_response(session_id, cert_der_b64, private_key)
    raw = base64.b64encode(xml.encode()).decode()
    response = client.parse_authn_request_response(
        raw, BINDING_HTTP_POST, {session_id: "return"}
    )
    assert response.session_id() == session_id


def test_direct_assertion_signature_policy_rejects_response_only_signature(
    rsa_keypair, tmp_path
):
    """A signed Response does not satisfy want_assertions_signed by itself."""
    private_key, _cert_pem, cert_der_b64 = rsa_keypair
    client = _assertion_signed_client(tmp_path, cert_der_b64)
    session_id, _ = client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    xml = _signed_auth_response(session_id, cert_der_b64, private_key)
    raw = base64.b64encode(xml.encode()).decode()
    with pytest.raises(AssertionError):
        client.parse_authn_request_response(
            raw, BINDING_HTTP_POST, {session_id: "return"}
        )


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
    assert info["method"] == "GET"
    assert info["url"].startswith(SSO + "?SAMLRequest=")
    assert dict(info["headers"])["Location"].startswith(SSO + "?SAMLRequest=")


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
                "idp": {
                    IDP: {
                        "single_sign_on_service": {
                            BINDING_HTTP_REDIRECT: SSO,
                            BINDING_HTTP_POST: SSO,
                        }
                    }
                },
                "authn_requests_signed": True,
            }
        },
        "key_file": str(key_file),
    }
    return Saml2Client(SPConfig().load(conf))


def test_prepare_authn_request_signs_redirect_with_key(rsa_keypair, tmp_path):
    """AuthnRequestsSigned signs Redirect requests with a detached signature."""
    client = _client_with_key(rsa_keypair, tmp_path)
    _sid, info = client.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)
    params = dict(urllib.parse.parse_qsl(dict(info["headers"])["Location"].split("?", 1)[1]))
    assert "SAMLRequest" in params
    assert params.get("SigAlg")
    assert "Signature" in params


def test_prepare_authn_request_signs_post_with_key(rsa_keypair, tmp_path):
    """AuthnRequestsSigned produces a verifiable enveloped POST signature."""
    _priv, cert_pem, _der = rsa_keypair
    client = _client_with_key(rsa_keypair, tmp_path)
    session_id, info = client.prepare_for_authenticate(
        entityid=IDP, binding=BINDING_HTTP_POST
    )
    match = re.search(r'name="SAMLRequest" value="([^"]+)"', info["data"])
    assert match is not None
    xml = base64.b64decode(html.unescape(match.group(1))).decode("utf-8")
    result = crypto.SamlVerifier.from_cert(cert_pem).verify_enveloped(xml)
    assert result.is_valid()
    assert session_id in result.signed_reference_ids()


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


def test_cache_structured_nameid_finds_legacy_pysaml2_key():
    """djangosaml2 decodes session NameIDs before cache lookup, so a structured
    NameID must still reach records persisted under pysaml2's legacy key."""
    from pygamlastan.compat.saml2.cache import Cache

    nid = _nid()
    legacy = ",".join(
        (
            "1=" + urllib.parse.quote(SP, safe=""),
            "2=" + urllib.parse.quote(TRANSIENT, safe=""),
            "4=subject-1",
        )
    )
    future = int(datetime.now(timezone.utc).timestamp()) + 3600
    cache = Cache()
    cache._db[legacy] = {
        IDP: (future, {"ava": {"mail": ["legacy@example.org"]}})
    }

    assert cache.get(nid, IDP)["ava"]["mail"] == ["legacy@example.org"]
    assert cache.entities(nid) == [IDP]


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
    resp_id = "fail-" + _fresh_ids()[0]
    unsigned = _failed_response(req_id, resp_id=resp_id)
    template = _signature_template(resp_id, cert_b64)
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


def test_parse_multi_idp_accepts_configured_issuer():
    """A multi-IdP SP can select a configured issuer from the response."""
    client = Saml2Client(SPConfig().load(_two_idp_config()))
    raw = base64.b64encode(_auth_response("id-req-x").encode("utf-8")).decode("ascii")
    resp = client.parse_authn_request_response(
        raw, BINDING_HTTP_POST, {"id-req-x": "r"}
    )
    assert resp.session_info()["issuer"] == IDP


def test_parse_ambiguous_idp_accepts_explicit_expected():
    """Passing expected_idp lets a multi-IdP SP process the response."""
    client = Saml2Client(SPConfig().load(_two_idp_config()))
    raw = base64.b64encode(_auth_response("id-req-x").encode("utf-8")).decode("ascii")
    resp = client.parse_authn_request_response(
        raw, BINDING_HTTP_POST, {"id-req-x": "r"}, expected_idp=IDP
    )
    assert resp.session_info()["issuer"] == IDP


def test_metadata_signing_flags_reflect_config(rsa_keypair, tmp_path):
    """SP metadata advertises the two dedicated pysaml2 signing settings."""
    priv, _cert_pem, _der = rsa_keypair
    key_file = tmp_path / "sp.key"
    key_file.write_bytes(priv)
    conf = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {"assertion_consumer_service": [(ACS, BINDING_HTTP_POST)]},
                "want_response_signed": True,
                "want_assertions_signed": True,
                "authn_requests_signed": True,
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


# --------------------------------------------------------------------------- #
# LogoutRequest signature verification (session-destroying path)
# --------------------------------------------------------------------------- #

def _session_nameid() -> NameID:
    return NameID(text="abc123hash", format=TRANSIENT, sp_name_qualifier=SP)


def _redirect_signed_logout(
    req_id: str, priv: bytes, relay_state: str | None = None
) -> tuple[str, str, str, str]:
    """A LogoutRequest over HTTP-Redirect with a valid detached signature.

    Returns (encoded_request, sig_alg, signature_b64, signed_query) - the
    values a web handler would forward from the query string. ``relay_state``
    is included in the signed portion when given (the SAML parameter order:
    SAMLRequest, RelayState, SigAlg).
    """
    signer = crypto.SamlSigner.from_pem(priv)
    sig_alg = signer.signature_method_uri()
    encoded = deflate_and_base64_encode(_logout_request(req_id))
    parts = ["SAMLRequest=" + urllib.parse.quote(encoded, safe="")]
    if relay_state is not None:
        parts.append("RelayState=" + urllib.parse.quote(relay_state, safe=""))
    parts.append("SigAlg=" + urllib.parse.quote(sig_alg, safe=""))
    signed_query = "&".join(parts)
    signature = signer.sign_redirect_query(signed_query.encode("utf-8"), sig_alg)
    return encoded, sig_alg, base64.b64encode(signature).decode("ascii"), signed_query


def _enveloped_signed_logout(req_id: str, cert_b64: str, priv: bytes) -> str:
    """A LogoutRequest carrying an enveloped XML-DSig over the request element."""
    unsigned = _logout_request(req_id)
    template = _signature_template(req_id, cert_b64)
    marker = "</saml:Issuer>"
    idx = unsigned.index(marker) + len(marker)
    return crypto.SamlSigner.from_pem(priv).sign_enveloped(
        unsigned[:idx] + template + unsigned[idx:]
    )


def test_handle_logout_request_valid_redirect_signature(rsa_keypair, tmp_path):
    """A LogoutRequest whose detached Redirect signature verifies against the
    IdP metadata certificate destroys the session (returns the response)."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    encoded, sig_alg, signature, signed_query = _redirect_signed_logout(
        "id-lr-redirect-ok", priv
    )
    info = client.handle_logout_request(
        encoded, _session_nameid(), BINDING_HTTP_REDIRECT,
        sig_alg=sig_alg, signature=signature, signed_query=signed_query,
    )
    assert info["headers"][0][1].startswith(IDPSLO + "?SAMLResponse=")


def test_logout_response_signing_uses_configured_algorithm(rsa_keypair, tmp_path):
    """The response to an IdP-initiated logout uses signing_algorithm rather
    than silently falling back to the key's default algorithm."""
    private_key, _cert_pem, _cert_der_b64 = rsa_keypair
    key_file = tmp_path / "sp-logout.key"
    key_file.write_bytes(private_key)
    conf = {
        **CONF,
        "key_file": str(key_file),
        "service": {
            "sp": {
                **CONF["service"]["sp"],
                "logout_responses_signed": True,
                "signing_algorithm": (
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
                ),
            }
        },
    }
    signing_client = Saml2Client(SPConfig().load(conf))
    encoded = deflate_and_base64_encode(
        _logout_request("id-lr-configured-response-alg")
    )

    with pytest.warns(UserWarning, match="No signing certificate"):
        info = signing_client.handle_logout_request(
            encoded, _session_nameid(), BINDING_HTTP_REDIRECT
        )

    query = dict(
        urllib.parse.parse_qsl(dict(info["headers"])["Location"].split("?", 1)[1])
    )
    assert query["SigAlg"].endswith("rsa-sha512")


def test_handle_logout_request_invalid_redirect_signature(rsa_keypair, tmp_path):
    """A forged/garbage Redirect signature is rejected, not downgraded to
    'unsigned'."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    encoded, sig_alg, _signature, signed_query = _redirect_signed_logout(
        "id-lr-redirect-bad", priv
    )
    forged = base64.b64encode(b"\x00" * 256).decode("ascii")
    with pytest.raises(ValueError, match="invalid LogoutRequest"):
        client.handle_logout_request(
            encoded, _session_nameid(), BINDING_HTTP_REDIRECT,
            sig_alg=sig_alg, signature=forged, signed_query=signed_query,
        )


def test_handle_logout_request_tampered_signed_query_rejected(rsa_keypair, tmp_path):
    """A valid signature over a DIFFERENT query (e.g. another request spliced in)
    does not verify."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    _enc, sig_alg, signature, _query = _redirect_signed_logout("id-lr-original", priv)
    other = deflate_and_base64_encode(_logout_request("id-lr-substituted"))
    other_query = (
        "SAMLRequest=" + urllib.parse.quote(other, safe="")
        + "&SigAlg=" + urllib.parse.quote(sig_alg, safe="")
    )
    with pytest.raises(ValueError, match="invalid LogoutRequest"):
        client.handle_logout_request(
            other, _session_nameid(), BINDING_HTTP_REDIRECT,
            sig_alg=sig_alg, signature=signature, signed_query=other_query,
        )


def test_handle_logout_request_substituted_request_rejected(rsa_keypair, tmp_path):
    """A VALID signed query from one LogoutRequest cannot vouch for a different
    (unsigned) LogoutRequest passed as the request argument: the SAMLRequest
    inside the signed query must decode to the exact message being processed."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    _legit, sig_alg, signature, signed_query = _redirect_signed_logout(
        "id-lr-legit-signed", priv
    )
    substituted = deflate_and_base64_encode(_logout_request("id-lr-substituted-req"))
    with pytest.raises(ValueError, match="invalid LogoutRequest"):
        client.handle_logout_request(
            substituted, _session_nameid(), BINDING_HTTP_REDIRECT,
            sig_alg=sig_alg, signature=signature, signed_query=signed_query,
        )


def test_handle_logout_request_sig_alg_mismatch_rejected(rsa_keypair, tmp_path):
    """The SigAlg used for verification must be the SigAlg inside the signed
    query, so the algorithm cannot be swapped out from under the signature."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    encoded, _sig_alg, signature, signed_query = _redirect_signed_logout(
        "id-lr-alg-swap", priv
    )
    with pytest.raises(ValueError, match="invalid LogoutRequest"):
        client.handle_logout_request(
            encoded, _session_nameid(), BINDING_HTTP_REDIRECT,
            sig_alg="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            signature=signature, signed_query=signed_query,
        )


def test_handle_logout_request_unsigned_rejected_when_cert_configured(rsa_keypair, tmp_path):
    """With an IdP signing certificate configured, an unsigned LogoutRequest
    fails closed instead of destroying the session."""
    _priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    encoded = deflate_and_base64_encode(_logout_request("id-lr-unsigned"))
    with pytest.raises(ValueError, match="invalid LogoutRequest"):
        client.handle_logout_request(encoded, _session_nameid(), BINDING_HTTP_REDIRECT)


def test_handle_logout_request_enveloped_signature_post(rsa_keypair, tmp_path):
    """A POST LogoutRequest with an enveloped XML-DSig bound to the request ID
    verifies and is accepted."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    signed_xml = _enveloped_signed_logout("id-lr-enveloped-ok", cert_der_b64, priv)
    raw = base64.b64encode(signed_xml.encode("utf-8")).decode("ascii")
    info = client.handle_logout_request(raw, _session_nameid(), BINDING_HTTP_POST)
    assert info["headers"][0][1].startswith(IDPSLO + "?SAMLResponse=")


def test_handle_logout_request_signs_post_response_for_post_only_idp(
    rsa_keypair, tmp_path
):
    """A POST request to an IdP with only POST SLO gets an enveloped, signed
    POST response that djangosaml2 can return as an auto-submitting form."""
    private_key, cert_pem, cert_der_b64 = rsa_keypair
    metadata_file = tmp_path / "post-only-idp.xml"
    metadata_file.write_text(
        _idp_metadata(cert_der_b64).replace(
            f'<md:SingleLogoutService Binding="{BINDING_HTTP_REDIRECT}"',
            f'<md:SingleLogoutService Binding="{BINDING_HTTP_POST}"',
            1,
        ),
        encoding="utf-8",
    )
    key_file = tmp_path / "post-response.key"
    key_file.write_bytes(private_key)
    config = {
        "entityid": SP,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(ACS, BINDING_HTTP_POST)],
                    "single_logout_service": [(SLO, BINDING_HTTP_POST)],
                },
                "logout_responses_signed": True,
            }
        },
        "metadata": {"local": [str(metadata_file)]},
        "key_file": str(key_file),
    }
    post_client = Saml2Client(SPConfig().load(config))
    signed_request = _enveloped_signed_logout(
        "id-lr-post-response", cert_der_b64, private_key
    )
    encoded = base64.b64encode(signed_request.encode()).decode()

    info = post_client.handle_logout_request(
        encoded, _session_nameid(), BINDING_HTTP_POST, relay_state="post-state"
    )

    assert info["method"] == "POST"
    assert info["url"] == IDPSLO
    match = re.search(r'name="SAMLResponse" value="([^"]+)"', info["data"])
    assert match is not None
    response_xml = base64.b64decode(html.unescape(match.group(1))).decode()
    verification = crypto.SamlVerifier.from_cert(cert_pem).verify_enveloped(
        response_xml
    )
    assert verification.is_valid()
    assert f'Destination="{IDPSLO}"' in response_xml


def test_handle_logout_request_tampered_signature_value_rejected(rsa_keypair, tmp_path):
    """A trusted-key enveloped signature whose SignatureValue was corrupted is
    rejected. This exercises the non-raising path: verify_all_enveloped
    RETURNS an invalid VerifyResult here (unlike the wrong-key case, which
    raises), so the loop must check is_valid() rather than accept reference
    IDs from an invalid result."""
    import re

    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    signed_xml = _enveloped_signed_logout("id-lr-sigval-tamper", cert_der_b64, priv)
    match = re.search(r"<ds:SignatureValue>([^<]+)</ds:SignatureValue>", signed_xml, re.S)
    assert match is not None
    value = match.group(1)
    flipped = ("B" if value.lstrip()[0] != "B" else "C") + value.lstrip()[1:]
    tampered = signed_xml.replace(value, flipped, 1)
    raw = base64.b64encode(tampered.encode("utf-8")).decode("ascii")
    with pytest.raises(ValueError, match="invalid LogoutRequest"):
        client.handle_logout_request(raw, _session_nameid(), BINDING_HTTP_POST)


def test_handle_logout_request_enveloped_wrong_key_rejected(rsa_keypair, rsa_keypair2, tmp_path):
    """An enveloped signature by a key NOT published in the IdP metadata is
    rejected."""
    _priv1, _pem1, cert1_der_b64 = rsa_keypair
    priv2, _pem2, cert2_der_b64 = rsa_keypair2
    client = _signed_client(tmp_path, cert1_der_b64)  # trusts only cert 1
    signed_xml = _enveloped_signed_logout("id-lr-wrong-key", cert2_der_b64, priv2)
    raw = base64.b64encode(signed_xml.encode("utf-8")).decode("ascii")
    with pytest.raises(ValueError, match="invalid LogoutRequest"):
        client.handle_logout_request(raw, _session_nameid(), BINDING_HTTP_POST)


def test_handle_logout_request_foreign_destination_rejected(client):
    """A LogoutRequest whose Destination names another SP's SLO endpoint is
    rejected: Destination must match one of THIS SP's configured endpoints."""
    encoded = deflate_and_base64_encode(
        _logout_request("id-lr-foreign-dest", destination="https://other-sp.example/slo")
    )
    with pytest.raises(ValueError, match="not a configured SLO endpoint"):
        client.handle_logout_request(encoded, _session_nameid(), BINDING_HTTP_REDIRECT)


def test_handle_logout_request_destination_for_other_binding_rejected(client):
    """A local Redirect-only SLO URL is not a valid POST destination merely
    because the URL appears elsewhere in this SP's endpoint configuration."""
    raw = base64.b64encode(
        _logout_request("id-lr-wrong-binding", destination=SLO).encode("utf-8")
    ).decode("ascii")
    with pytest.raises(ValueError, match="not a configured SLO endpoint.*HTTP-POST"):
        client.handle_logout_request(raw, _session_nameid(), BINDING_HTTP_POST)


def test_handle_logout_request_without_destination_accepted(client):
    """Destination is optional; only a present value is endpoint-bound."""
    encoded = deflate_and_base64_encode(
        _logout_request("id-lr-no-destination", destination=None)
    )
    with pytest.warns(UserWarning, match="No signing certificate"):
        info = client.handle_logout_request(
            encoded, _session_nameid(), BINDING_HTTP_REDIRECT
        )
    assert info["headers"][0][1].startswith(IDPSLO + "?SAMLResponse=")


def test_handle_logout_request_signed_foreign_destination_rejected(rsa_keypair, tmp_path):
    """The exact attack: a request VALIDLY SIGNED by the trusted IdP but
    addressed to a different SP's SLO endpoint passes issuer/signature/subject
    checks yet must still be rejected on Destination."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    signer = crypto.SamlSigner.from_pem(priv)
    sig_alg = signer.signature_method_uri()
    encoded = deflate_and_base64_encode(
        _logout_request("id-lr-signed-foreign", destination="https://other-sp.example/slo")
    )
    signed_query = (
        "SAMLRequest=" + urllib.parse.quote(encoded, safe="")
        + "&SigAlg=" + urllib.parse.quote(sig_alg, safe="")
    )
    signature = base64.b64encode(
        signer.sign_redirect_query(signed_query.encode("utf-8"), sig_alg)
    ).decode("ascii")
    with pytest.raises(ValueError, match="not a configured SLO endpoint"):
        client.handle_logout_request(
            encoded, _session_nameid(), BINDING_HTTP_REDIRECT,
            sig_alg=sig_alg, signature=signature, signed_query=signed_query,
        )


def test_handle_logout_request_incomplete_redirect_signature_rejected(rsa_keypair, tmp_path):
    """A partial signature tuple (e.g. SigAlg present, Signature stripped) is a
    hard error - it must never be downgraded to unsigned handling."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    encoded, sig_alg, _signature, signed_query = _redirect_signed_logout(
        "id-lr-partial-sig", priv
    )
    with pytest.raises(ValueError, match="incomplete redirect signature"):
        client.handle_logout_request(
            encoded, _session_nameid(), BINDING_HTTP_REDIRECT,
            sig_alg=sig_alg, signed_query=signed_query,  # no signature
        )


def test_handle_logout_request_incomplete_tuple_rejected_without_cert(client):
    """The incomplete-tuple check runs BEFORE the certificate lookup: a known
    IdP without metadata keys (the no-certificate development fallback) must
    not accept SigAlg with a stripped Signature as 'unsigned'."""
    encoded = deflate_and_base64_encode(_logout_request("id-lr-partial-nocert"))
    signed_query = "SAMLRequest=" + urllib.parse.quote(encoded, safe="")
    with pytest.raises(ValueError, match="incomplete redirect signature"):
        client.handle_logout_request(
            encoded, _session_nameid(), BINDING_HTTP_REDIRECT,
            sig_alg="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            signed_query=signed_query,  # no signature
        )


def test_handle_logout_request_future_issue_instant_rejected(client):
    """A far-future IssueInstant is rejected (beyond the 180s skew): upstream
    validation checks only NotOnOrAfter, and without this a request could pin
    a replay entry expiring 24h after that future instant - unbounded cache
    retention, unauthenticated in the no-certificate fallback."""
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    encoded = deflate_and_base64_encode(
        _logout_request("id-lr-future", issue_instant=future)
    )
    with pytest.warns(UserWarning, match="No signing certificate"):
        with pytest.raises(ValueError, match="in the future"):
            client.handle_logout_request(
                encoded, _session_nameid(), BINDING_HTTP_REDIRECT
            )


def test_handle_logout_request_relay_state_bound(rsa_keypair, tmp_path):
    """RelayState is part of the signed query: a matching echo is accepted (and
    carried on the response redirect); a substituted one is rejected."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    encoded, sig_alg, signature, signed_query = _redirect_signed_logout(
        "id-lr-rs-ok", priv, relay_state="rs-signed-1"
    )
    info = client.handle_logout_request(
        encoded, _session_nameid(), BINDING_HTTP_REDIRECT, relay_state="rs-signed-1",
        sig_alg=sig_alg, signature=signature, signed_query=signed_query,
    )
    location = info["headers"][0][1]
    params = dict(urllib.parse.parse_qsl(location.split("?", 1)[1]))
    assert params["RelayState"] == "rs-signed-1"

    encoded2, sig_alg2, signature2, signed_query2 = _redirect_signed_logout(
        "id-lr-rs-swap", priv, relay_state="rs-signed-2"
    )
    with pytest.raises(ValueError, match="RelayState does not match"):
        client.handle_logout_request(
            encoded2, _session_nameid(), BINDING_HTTP_REDIRECT,
            relay_state="attacker-controlled",
            sig_alg=sig_alg2, signature=signature2, signed_query=signed_query2,
        )


def test_handle_logout_request_unsigned_relay_state_rejected(rsa_keypair, tmp_path):
    """A RelayState supplied by the caller when the signed query carries none
    is rejected: an unsigned RelayState cannot ride along a valid signature."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client = _signed_client(tmp_path, cert_der_b64)
    encoded, sig_alg, signature, signed_query = _redirect_signed_logout(
        "id-lr-rs-inject", priv
    )
    with pytest.raises(ValueError, match="RelayState does not match"):
        client.handle_logout_request(
            encoded, _session_nameid(), BINDING_HTTP_REDIRECT,
            relay_state="injected-unsigned",
            sig_alg=sig_alg, signature=signature, signed_query=signed_query,
        )


def test_handle_logout_request_stale_without_notonorafter_rejected(client):
    """A LogoutRequest that declares no NotOnOrAfter is subject to the shim's
    own age limit, so a captured request cannot outlive its replay-cache entry
    and be accepted again after the entry expires."""
    old = (datetime.now(timezone.utc) - timedelta(hours=25)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    encoded = deflate_and_base64_encode(
        _logout_request("id-lr-ancient", issue_instant=old)
    )
    with pytest.warns(UserWarning, match="No signing certificate"):
        with pytest.raises(ValueError, match="maximum accepted age"):
            client.handle_logout_request(
                encoded, _session_nameid(), BINDING_HTTP_REDIRECT
            )


def test_handle_logout_request_unknown_expected_idp_rejected(client):
    """A caller-supplied expected_idp that is neither configured nor present in
    metadata must not reach the no-certificate development fallback: an
    arbitrary entity ID would otherwise become a trusted unsigned issuer."""
    unknown = "https://unknown.example/idp"
    encoded = deflate_and_base64_encode(_logout_request("id-lr-unknown-idp", issuer=unknown))
    with pytest.raises(ValueError, match="unknown IdP"):
        client.handle_logout_request(
            encoded, _session_nameid(), BINDING_HTTP_REDIRECT, expected_idp=unknown
        )


def test_handle_logout_request_replay_rejected(rsa_keypair, tmp_path):
    """A captured, validly signed LogoutRequest is one-time use: a second
    submission - even through a freshly constructed client instance - is
    rejected as a replay instead of destroying the session again."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    client1 = _signed_client(tmp_path, cert_der_b64)
    encoded, sig_alg, signature, signed_query = _redirect_signed_logout(
        "id-lr-replayed", priv
    )
    kwargs = dict(sig_alg=sig_alg, signature=signature, signed_query=signed_query)
    info = client1.handle_logout_request(
        encoded, _session_nameid(), BINDING_HTTP_REDIRECT, **kwargs
    )
    assert info["headers"][0][1].startswith(IDPSLO + "?SAMLResponse=")
    client2 = _signed_client(tmp_path, cert_der_b64)
    with pytest.raises(ValueError, match="replay"):
        client2.handle_logout_request(
            encoded, _session_nameid(), BINDING_HTTP_REDIRECT, **kwargs
        )


def test_handle_logout_request_no_cert_warns_and_accepts(client):
    """The explicit development opt-out: with no signing certificate for the
    IdP AND allow_unsigned_logout_requests enabled (as CONF does), an unsigned
    LogoutRequest is accepted with a warning."""
    encoded = deflate_and_base64_encode(_logout_request("id-lr-no-cert"))
    with pytest.warns(UserWarning, match="No signing certificate"):
        info = client.handle_logout_request(encoded, _session_nameid(), BINDING_HTTP_REDIRECT)
    assert info["headers"][0][1].startswith(IDPSLO + "?SAMLResponse=")


def test_handle_logout_request_no_cert_fails_closed_by_default():
    """Without the explicit allow_unsigned_logout_requests opt-in, a missing
    IdP signing certificate fails closed: a production metadata omission must
    not silently downgrade the session-destroying endpoint to accepting
    unsigned requests."""
    conf = {**CONF}
    sp = {**CONF["service"]["sp"]}
    sp["allow_unsigned_logout_requests"] = False
    conf["service"] = {"sp": sp}
    client = Saml2Client(SPConfig().load(conf))
    assert client.config.allow_unsigned_logout_requests is False
    encoded = deflate_and_base64_encode(_logout_request("id-lr-fail-closed"))
    with pytest.raises(ValueError, match="allow_unsigned_logout_requests"):
        client.handle_logout_request(encoded, _session_nameid(), BINDING_HTTP_REDIRECT)


def test_handle_logout_request_excessive_notonorafter_rejected(client):
    """A request-declared NotOnOrAfter beyond the maximum accepted validity
    window is rejected: an attacker-chosen date years ahead would otherwise
    pin a replay-cache entry until then and grow the process-wide cache
    without bound."""
    far = (datetime.now(timezone.utc) + timedelta(days=365)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    request = f"""<?xml version='1.0' encoding='UTF-8'?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-lr-far-noa" IssueInstant="{ts}" NotOnOrAfter="{far}" Version="2.0" Destination="{SLO}">
  <saml:Issuer>{IDP}</saml:Issuer>
  <saml:NameID Format="{TRANSIENT}" SPNameQualifier="{SP}">abc123hash</saml:NameID>
</samlp:LogoutRequest>"""
    encoded = deflate_and_base64_encode(request)
    with pytest.warns(UserWarning, match="No signing certificate"):
        with pytest.raises(ValueError, match="maximum accepted validity window"):
            client.handle_logout_request(
                encoded, _session_nameid(), BINDING_HTTP_REDIRECT
            )


# --------------------------------------------------------------------------- #
# Key rollover: metadata publishing several signing certificates
# --------------------------------------------------------------------------- #

def test_signed_response_accepted_with_rollover_cert(rsa_keypair, rsa_keypair2, tmp_path):
    """Metadata publishes two signing certificates (rollover); a Response signed
    with the SECOND one still verifies (not just the first)."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    _priv2, _pem2, other_cert_b64 = rsa_keypair2
    # The signer's certificate is listed second in metadata.
    client = _signed_client(tmp_path, other_cert_b64, cert_der_b64)
    session_id, _ = client.prepare_for_authenticate(binding=BINDING_HTTP_REDIRECT)
    signed = _signed_auth_response(session_id, cert_der_b64, priv)
    raw = base64.b64encode(signed.encode("utf-8")).decode("ascii")
    resp = client.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})
    assert resp.session_info()["issuer"] == IDP


def test_logout_redirect_rollover_survives_raising_verifier(ec_keypair, rsa_keypair, tmp_path):
    """A retired certificate whose key type mismatches the signature algorithm
    makes verify_redirect_query RAISE (SamlCryptoError, not a False return);
    rollover verification must try the remaining published certificates
    instead of aborting at the first one."""
    _ec_priv, _ec_pem, ec_cert_b64 = ec_keypair
    priv, _cert_pem, rsa_cert_b64 = rsa_keypair
    # The EC certificate is published FIRST; the RSA signer's cert second.
    client = _signed_client(tmp_path, ec_cert_b64, rsa_cert_b64)
    encoded, sig_alg, signature, signed_query = _redirect_signed_logout(
        "id-lr-ec-first", priv
    )
    info = client.handle_logout_request(
        encoded, _session_nameid(), BINDING_HTTP_REDIRECT,
        sig_alg=sig_alg, signature=signature, signed_query=signed_query,
    )
    assert info["headers"][0][1].startswith(IDPSLO + "?SAMLResponse=")


def test_logout_request_verified_with_rollover_cert(rsa_keypair, rsa_keypair2, tmp_path):
    """A LogoutRequest signed with the second published rollover certificate is
    accepted, over both the Redirect and enveloped representations."""
    priv, _cert_pem, cert_der_b64 = rsa_keypair
    _priv2, _pem2, other_cert_b64 = rsa_keypair2
    client = _signed_client(tmp_path, other_cert_b64, cert_der_b64)
    # Redirect: detached signature by the second cert's key.
    encoded, sig_alg, signature, signed_query = _redirect_signed_logout(
        "id-lr-rollover-redirect", priv
    )
    info = client.handle_logout_request(
        encoded, _session_nameid(), BINDING_HTTP_REDIRECT,
        sig_alg=sig_alg, signature=signature, signed_query=signed_query,
    )
    assert info["headers"][0][1].startswith(IDPSLO + "?SAMLResponse=")
    # Enveloped: XML-DSig by the second cert's key.
    signed_xml = _enveloped_signed_logout("id-lr-rollover-env", cert_der_b64, priv)
    raw = base64.b64encode(signed_xml.encode("utf-8")).decode("ascii")
    info = client.handle_logout_request(raw, _session_nameid(), BINDING_HTTP_POST)
    assert info["headers"][0][1].startswith(IDPSLO + "?SAMLResponse=")


# --------------------------------------------------------------------------- #
# Replay-cache scoping
# --------------------------------------------------------------------------- #

def test_replay_rejected_across_client_instances():
    """The replay cache is process-scoped: an assertion accepted through one
    Saml2Client instance is rejected by a freshly constructed one (e.g. a
    per-request client)."""
    client1 = Saml2Client(SPConfig().load(CONF))
    session_id, _ = client1.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)
    raw = base64.b64encode(_auth_response(session_id).encode("utf-8")).decode("ascii")
    client1.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})
    client2 = Saml2Client(SPConfig().load(CONF))
    with pytest.raises(AssertionError):
        client2.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})


def test_replay_cache_injectable():
    """A caller-supplied replay cache replaces the process-level one, so a
    multi-process deployment can share replay state its own way."""
    from pygamlastan import security

    client1 = Saml2Client(SPConfig().load(CONF), replay_cache=security.InMemoryReplayCache())
    session_id, _ = client1.prepare_for_authenticate(entityid=IDP, binding=BINDING_HTTP_REDIRECT)
    raw = base64.b64encode(_auth_response(session_id).encode("utf-8")).decode("ascii")
    client1.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})
    # The same response replays against the same injected cache...
    with pytest.raises(AssertionError):
        client1.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})
    # ...but a client with its own isolated cache accepts it: the injected
    # cache, not the process cache, was consulted.
    client2 = Saml2Client(SPConfig().load(CONF), replay_cache=security.InMemoryReplayCache())
    resp = client2.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})
    assert resp.session_id() == session_id


def test_replay_cache_scopes_identical_assertion_ids_by_sp_and_idp():
    """A trusted IdP or SP cannot reserve an assertion ID in another trust
    context, while a repeat inside the original context remains a replay."""
    from pygamlastan import security

    cache = security.InMemoryReplayCache()
    shared_assertion_id = "id-shared-across-trust-contexts"
    other_idp = "https://other.idp.example/md"

    def parse(client_obj, response_xml, request_id, expected_idp):
        raw = base64.b64encode(response_xml.encode("utf-8")).decode("ascii")
        return client_obj.parse_authn_request_response(
            raw,
            BINDING_HTTP_POST,
            {request_id: "relay"},
            expected_idp=expected_idp,
        )

    multi_idp_client = Saml2Client(
        SPConfig().load(_two_idp_config()), replay_cache=cache
    )
    first_xml = _auth_response(
        "id-scope-idp-1",
        resp_id="id-response-scope-idp-1",
        assert_id=shared_assertion_id,
    )
    second_xml = _auth_response(
        "id-scope-idp-2",
        resp_id="id-response-scope-idp-2",
        assert_id=shared_assertion_id,
    ).replace(IDP, other_idp)
    assert parse(multi_idp_client, first_xml, "id-scope-idp-1", IDP)
    assert parse(multi_idp_client, second_xml, "id-scope-idp-2", other_idp)

    other_sp = "https://other-sp.example/metadata"
    other_acs = "https://other-sp.example/acs"
    other_sp_config = {
        "entityid": other_sp,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [
                        (other_acs, BINDING_HTTP_POST)
                    ]
                },
                "want_response_signed": False,
                "idp": {
                    IDP: {
                        "single_sign_on_service": {
                            BINDING_HTTP_REDIRECT: SSO
                        }
                    }
                },
            }
        },
    }
    other_sp_client = Saml2Client(
        SPConfig().load(other_sp_config), replay_cache=cache
    )
    third_xml = _auth_response(
        "id-scope-sp-2",
        resp_id="id-response-scope-sp-2",
        assert_id=shared_assertion_id,
    ).replace(ACS, other_acs).replace(SP, other_sp)
    assert parse(other_sp_client, third_xml, "id-scope-sp-2", IDP)

    with pytest.raises(AssertionError):
        parse(multi_idp_client, first_xml, "id-scope-idp-1", IDP)


def test_replay_cache_scopes_assertions_and_logout_requests():
    """The same raw ID may occur once in each SAML message kind, in either
    order, without weakening repeat detection inside either kind."""
    from pygamlastan import security

    cache = security.InMemoryReplayCache()
    scoped_client = Saml2Client(SPConfig().load(CONF), replay_cache=cache)

    assertion_first_id = "id-assertion-before-logout"
    response = _auth_response(
        "id-request-assertion-first",
        resp_id="id-response-assertion-first",
        assert_id=assertion_first_id,
    )
    raw = base64.b64encode(response.encode("utf-8")).decode("ascii")
    scoped_client.parse_authn_request_response(
        raw, BINDING_HTTP_POST, {"id-request-assertion-first": "relay"}
    )
    logout = deflate_and_base64_encode(_logout_request(assertion_first_id))
    with pytest.warns(UserWarning, match="No signing certificate"):
        scoped_client.handle_logout_request(
            logout, _session_nameid(), BINDING_HTTP_REDIRECT
        )
    with pytest.warns(UserWarning, match="No signing certificate"):
        with pytest.raises(ValueError, match="replay"):
            scoped_client.handle_logout_request(
                logout, _session_nameid(), BINDING_HTTP_REDIRECT
            )

    logout_first_id = "id-logout-before-assertion"
    logout_first = deflate_and_base64_encode(_logout_request(logout_first_id))
    with pytest.warns(UserWarning, match="No signing certificate"):
        scoped_client.handle_logout_request(
            logout_first, _session_nameid(), BINDING_HTTP_REDIRECT
        )
    response_after = _auth_response(
        "id-request-logout-first",
        resp_id="id-response-logout-first",
        assert_id=logout_first_id,
    )
    raw_after = base64.b64encode(response_after.encode("utf-8")).decode("ascii")
    scoped_client.parse_authn_request_response(
        raw_after, BINDING_HTTP_POST, {"id-request-logout-first": "relay"}
    )
    with pytest.raises(AssertionError):
        scoped_client.parse_authn_request_response(
            raw_after, BINDING_HTTP_POST, {"id-request-logout-first": "relay"}
        )


def test_scoped_replay_cache_uses_distinct_ascii_protocol_keys():
    """The private adapter keeps the two-argument custom-cache protocol while
    encoding delimiter-heavy and Unicode scope values without collisions."""
    from pygamlastan.compat.saml2 import client as client_mod

    class RecordingCache:
        def __init__(self):
            self.keys = []
            self.seen = set()
            self.cleanups = 0

        def check_and_insert(self, message_id, expiry):
            self.keys.append(message_id)
            if message_id in self.seen:
                return False
            self.seen.add(message_id)
            return True

        def cleanup(self):
            self.cleanups += 1

    cache = RecordingCache()
    expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
    first = client_mod._ScopedReplayCache(cache, "assertion", "sp,a", "idp:b")
    second = client_mod._ScopedReplayCache(cache, "assertion", "sp", "a,idp:b")

    assert first.check_and_insert("id-å", expiry)
    assert second.check_and_insert("id-å", expiry)
    assert not first.check_and_insert("id-å", expiry)
    assert len(cache.seen) == 2
    assert all(key.startswith("pygamlastan-replay:v1:") for key in cache.keys)
    assert all(key.isascii() for key in cache.keys)
    first.cleanup()
    assert cache.cleanups == 1


def test_replay_cache_periodic_cleanup(monkeypatch):
    """The processing paths schedule (throttled) cache.cleanup() so expired
    entries are evicted: gamlastan's check_and_insert never removes other
    entries and validation never calls cleanup(), so without this the
    process-lifetime cache would grow without bound."""
    from pygamlastan.compat.saml2 import client as client_mod

    def force_next_cleanup():
        # Clearing the per-cache table makes every cache due for cleanup.
        monkeypatch.setattr(client_mod, "_replay_cleanup_times", {})

    class RecordingCache:
        def __init__(self):
            self.cleanups = 0

        def check_and_insert(self, id, expiry):
            return True

        def cleanup(self):
            self.cleanups += 1

    cache = RecordingCache()
    c = Saml2Client(SPConfig().load(CONF), replay_cache=cache)

    def parse_once(client_obj):
        session_id, _ = client_obj.prepare_for_authenticate(
            entityid=IDP, binding=BINDING_HTTP_REDIRECT
        )
        raw = base64.b64encode(_auth_response(session_id).encode("utf-8")).decode("ascii")
        client_obj.parse_authn_request_response(raw, BINDING_HTTP_POST, {session_id: "r"})

    # Response path: a cache with no recorded cleanup gets exactly one.
    force_next_cleanup()
    parse_once(c)
    assert cache.cleanups == 1
    # Within the throttle interval, no further cleanup runs for this cache.
    parse_once(c)
    assert cache.cleanups == 1
    # The throttle is PER CACHE: a second, independent cache is cleaned right
    # away even though the first cache just consumed its own slot.
    cache2 = RecordingCache()
    c2 = Saml2Client(SPConfig().load(CONF), replay_cache=cache2)
    parse_once(c2)
    assert cache2.cleanups == 1
    assert cache.cleanups == 1
    # Logout path schedules cleanup too (throttle reset to force it).
    force_next_cleanup()
    encoded = deflate_and_base64_encode(_logout_request("id-lr-cleanup"))
    with pytest.warns(UserWarning, match="No signing certificate"):
        c.handle_logout_request(encoded, _session_nameid(), BINDING_HTTP_REDIRECT)
    assert cache.cleanups == 2


def test_inmemory_replay_cache_cleanup_evicts_expired():
    """InMemoryReplayCache.cleanup() removes expired entries (check_and_insert
    alone never shrinks the map)."""
    from pygamlastan import security

    cache = security.InMemoryReplayCache()
    now = datetime.now(timezone.utc)
    assert cache.check_and_insert("expired-entry", now - timedelta(seconds=1))
    assert cache.check_and_insert("live-entry", now + timedelta(hours=1))
    assert len(cache) == 2
    cache.cleanup()
    assert len(cache) == 1
