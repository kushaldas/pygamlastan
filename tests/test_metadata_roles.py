"""An entity can carry a legacy role beside a SAML 2.0 one.

Each role declares the protocols it speaks in ``protocolSupportEnumeration``. A key
or an endpoint published only for a legacy role must not be offered for a SAML 2.0
message, whichever role is listed first. The accessors therefore read only the
SAML 2.0 roles by default, and ``protocol=None`` reads every role.
"""

import base64

import pytest

from pygamlastan import metadata
from pygamlastan.compat.saml2.config import SPConfig

SAML2 = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML11 = "urn:oasis:names:tc:SAML:1.1:protocol"

IDP = "https://idp.example.org/idp"
SP = "https://sp.example.org/sp"

LEGACY_SSO = "https://idp.example.org/legacy/sso"
SAML2_SSO = "https://idp.example.org/saml2/sso"
LEGACY_ACS = "https://sp.example.org/legacy/acs"
SAML2_ACS = "https://sp.example.org/saml2/acs"
LEGACY_SLO = "https://idp.example.org/legacy/slo"
SAML2_SLO = "https://idp.example.org/saml2/slo"

HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
SHIB1_SSO = "urn:mace:shibboleth:1.0:profiles:AuthnRequest"
SAML1_POST = "urn:oasis:names:tc:SAML:1.0:profiles:browser-post"

LEGACY_FORMAT = "urn:mace:shibboleth:1.0:nameIdentifier"
SAML2_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"


def _key(cert_b64, use=None):
    use_attr = f' use="{use}"' if use else ""
    return (
        f"<md:KeyDescriptor{use_attr}>"
        '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>'
        f"<ds:X509Certificate>{cert_b64}</ds:X509Certificate>"
        "</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
    )


def _der(cert_b64):
    return base64.b64decode(cert_b64)


def _idp_metadata(*, legacy_cert, saml2_cert, legacy_first=True):
    legacy = (
        f'<md:IDPSSODescriptor protocolSupportEnumeration="{SAML11} urn:mace:shibboleth:1.0">'
        f"{_key(legacy_cert, 'signing')}"
        f"<md:NameIDFormat>{LEGACY_FORMAT}</md:NameIDFormat>"
        f'<md:SingleLogoutService Binding="{HTTP_REDIRECT}" Location="{LEGACY_SLO}"/>'
        f'<md:SingleSignOnService Binding="{SHIB1_SSO}" Location="{LEGACY_SSO}"/>'
        "</md:IDPSSODescriptor>"
    )
    saml2 = (
        f'<md:IDPSSODescriptor protocolSupportEnumeration="{SAML2}">'
        f"{_key(saml2_cert, 'signing')}"
        f"<md:NameIDFormat>{SAML2_FORMAT}</md:NameIDFormat>"
        f'<md:SingleLogoutService Binding="{HTTP_REDIRECT}" Location="{SAML2_SLO}"/>'
        f'<md:SingleSignOnService Binding="{HTTP_REDIRECT}" Location="{SAML2_SSO}"/>'
        "</md:IDPSSODescriptor>"
    )
    roles = legacy + saml2 if legacy_first else saml2 + legacy
    return (
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{IDP}">{roles}</md:EntityDescriptor>'
    )


def _sp_metadata(*, legacy_cert, saml2_cert, legacy_first=True):
    def acs_block(name):
        return (
            '<md:AttributeConsumingService index="0" isDefault="true">'
            f"<md:ServiceName xml:lang=\"en\">{name}</md:ServiceName>"
            f'<md:RequestedAttribute Name="{name}" isRequired="true"/>'
            "</md:AttributeConsumingService>"
        )

    legacy = (
        f'<md:SPSSODescriptor protocolSupportEnumeration="{SAML11}" AuthnRequestsSigned="false">'
        f"{_key(legacy_cert)}"
        f"<md:NameIDFormat>{LEGACY_FORMAT}</md:NameIDFormat>"
        f'<md:SingleLogoutService Binding="{HTTP_REDIRECT}" Location="{LEGACY_SLO}"/>'
        f'<md:AssertionConsumerService Binding="{SAML1_POST}" Location="{LEGACY_ACS}" index="0"/>'
        f"{acs_block('legacyAttr')}"
        "</md:SPSSODescriptor>"
    )
    saml2 = (
        f'<md:SPSSODescriptor protocolSupportEnumeration="{SAML2}">'
        f"{_key(saml2_cert)}"
        f"<md:NameIDFormat>{SAML2_FORMAT}</md:NameIDFormat>"
        f'<md:SingleLogoutService Binding="{HTTP_REDIRECT}" Location="{SAML2_SLO}"/>'
        f'<md:AssertionConsumerService Binding="{HTTP_POST}" Location="{SAML2_ACS}" index="0"/>'
        f"{acs_block('mail')}"
        "</md:SPSSODescriptor>"
    )
    roles = legacy + saml2 if legacy_first else saml2 + legacy
    return (
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{SP}">{roles}</md:EntityDescriptor>'
    )


def _locations(endpoints):
    return sorted(e.location for e in endpoints)


@pytest.mark.parametrize("legacy_first", [True, False])
def test_idp_accessors_read_only_the_saml2_role_by_default(rsa_keypair, rsa_keypair2, legacy_first):
    legacy, saml2 = rsa_keypair[2], rsa_keypair2[2]
    ed = metadata.parse_entity(
        _idp_metadata(legacy_cert=legacy, saml2_cert=saml2, legacy_first=legacy_first)
    )

    assert ed.signing_certificates("idp") == [_der(saml2)]
    assert _locations(ed.single_sign_on_services()) == [SAML2_SSO]
    assert _locations(ed.single_logout_services("idp")) == [SAML2_SLO]
    assert ed.name_id_formats("idp") == [SAML2_FORMAT]

    # protocol=None reads every role, for inspection tools.
    assert sorted(ed.signing_certificates("idp", protocol=None)) == sorted(
        [_der(legacy), _der(saml2)]
    )
    assert _locations(ed.single_sign_on_services(protocol=None)) == sorted([LEGACY_SSO, SAML2_SSO])
    assert _locations(ed.single_logout_services("idp", protocol=None)) == sorted(
        [LEGACY_SLO, SAML2_SLO]
    )
    assert sorted(ed.name_id_formats("idp", protocol=None)) == sorted([LEGACY_FORMAT, SAML2_FORMAT])

    # Another protocol selects that protocol's roles.
    assert ed.signing_certificates("idp", protocol=SAML11) == [_der(legacy)]
    assert _locations(ed.single_sign_on_services(protocol=SAML11)) == [LEGACY_SSO]


@pytest.mark.parametrize("legacy_first", [True, False])
def test_sp_accessors_read_only_the_saml2_role_by_default(rsa_keypair, rsa_keypair2, legacy_first):
    legacy, saml2 = rsa_keypair[2], rsa_keypair2[2]
    ed = metadata.parse_entity(
        _sp_metadata(legacy_cert=legacy, saml2_cert=saml2, legacy_first=legacy_first)
    )

    assert ed.signing_certificates("sp") == [_der(saml2)]
    assert ed.encryption_certificates("sp") == [_der(saml2)]
    assert _locations(ed.assertion_consumer_services()) == [SAML2_ACS]
    assert _locations(ed.single_logout_services("sp")) == [SAML2_SLO]
    assert ed.name_id_formats("sp") == [SAML2_FORMAT]
    required, optional = ed.requested_attributes()
    assert [a.name for a in required] == ["mail"], "the legacy role's attributes must not leak in"

    assert sorted(ed.signing_certificates("sp", protocol=None)) == sorted(
        [_der(legacy), _der(saml2)]
    )
    assert sorted(ed.encryption_certificates("sp", protocol=None)) == sorted(
        [_der(legacy), _der(saml2)]
    )
    assert _locations(ed.assertion_consumer_services(protocol=None)) == sorted(
        [LEGACY_ACS, SAML2_ACS]
    )
    required_all, _ = ed.requested_attributes(protocol=None)
    assert sorted(a.name for a in required_all) == ["legacyAttr", "mail"]


def test_a_certificate_listed_in_both_roles_is_returned_once(rsa_keypair):
    # Common in real metadata: one key, published for both a legacy and a SAML 2.0 role.
    shared = rsa_keypair[2]
    ed = metadata.parse_entity(_idp_metadata(legacy_cert=shared, saml2_cert=shared))
    assert ed.signing_certificates("idp") == [_der(shared)]
    assert ed.signing_certificates("idp", protocol=None) == [_der(shared), _der(shared)]


def test_the_compat_layer_does_not_trust_a_key_published_only_for_a_legacy_role(
    tmp_path, rsa_keypair, rsa_keypair2
):
    legacy, saml2 = rsa_keypair[2], rsa_keypair2[2]

    def config(idp_xml):
        path = tmp_path / "idp.xml"
        path.write_text(idp_xml, encoding="utf-8")
        return SPConfig().load(
            {
                "service": {"sp": {"want_response_signed": True}},
                "metadata": {"local": [str(path)]},
            }
        )

    # Both roles carry a key: only the SAML 2.0 role's verifies a SAML 2.0 response.
    both = config(_idp_metadata(legacy_cert=legacy, saml2_cert=saml2))
    assert both.idp_signing_certs(IDP) == [_der(saml2)]

    # A key only in the legacy role is not offered, and the error says why.
    legacy_only_xml = (
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{IDP}">'
        f'<md:IDPSSODescriptor protocolSupportEnumeration="{SAML11}">'
        f"{_key(legacy, 'signing')}"
        f'<md:SingleSignOnService Binding="{SHIB1_SSO}" Location="{LEGACY_SSO}"/>'
        "</md:IDPSSODescriptor>"
        f'<md:IDPSSODescriptor protocolSupportEnumeration="{SAML2}">'
        f'<md:SingleSignOnService Binding="{HTTP_REDIRECT}" Location="{SAML2_SSO}"/>'
        "</md:IDPSSODescriptor></md:EntityDescriptor>"
    )
    only_legacy = config(legacy_only_xml)
    with pytest.raises(ValueError, match="only in roles that do not declare SAML 2.0"):
        only_legacy.idp_signing_certs(IDP)
