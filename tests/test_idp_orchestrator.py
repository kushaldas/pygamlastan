"""The IdP response orchestrator (`pygamlastan.idp.ResponseEngine`).

The engine's logic is tested in gamlastan itself; these tests cover what the
binding adds: the Python types, argument handling, and error mapping.
"""

from datetime import datetime, timedelta, timezone

import pytest

import pygamlastan
from pygamlastan import core, crypto, idp, metadata, profiles, xml

IDP = "https://idp.example.org/idp"
SP = "https://sp.example.org/sp"
ACS = "https://sp.example.org/acs"

SP_METADATA = (
    '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
    f'entityID="{SP}"><md:SPSSODescriptor '
    'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
    f'Location="{ACS}" index="0" isDefault="true"/>'
    "</md:SPSSODescriptor></md:EntityDescriptor>"
)


def _request_xml(attrs="", subject="", policy=""):
    return (
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" '
        f'IssueInstant="2026-06-24T10:00:00Z" Destination="{IDP}/sso" '
        f'AssertionConsumerServiceURL="{ACS}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {attrs}>'
        f"<saml:Issuer>{SP}</saml:Issuer>{subject}{policy}</samlp:AuthnRequest>"
    )


def _params(request_xml=None, sp_metadata=SP_METADATA):
    req = xml.parse_authn_request(request_xml or _request_xml())
    entity = metadata.parse_entity(SP_METADATA)
    processed = profiles.process_authn_request(req, entity)
    return idp.ResponseParams(processed, metadata.parse_entity(sp_metadata))


def _engine(rsa_keypair, *, policy=None, idents=None, assertions=None, release="policy"):
    priv, _cert, cert_b64 = rsa_keypair
    broker = idp.AuthnBroker()
    ref = broker.add(core.AUTHN_CONTEXT_PASSWORD, "/login/password", 1)
    signer = crypto.SamlSigner(crypto.KeysManager.build_idp(priv))
    engine = idp.ResponseEngine(
        IDP,
        policy or idp.ReleasePolicy(),
        idents or idp.IdentDb(IDP),
        broker,
        signer,
        cert_b64,
        assertions=assertions,
        release=release,
    )
    return engine, ref


def _subject(ref, user="alice", attributes=None, **kw):
    if attributes is None:
        attributes = [core.Attribute("mail", values=["alice@example.org"])]
    return idp.AuthenticatedSubject(user, attributes, idp.AuthnMethodRef.broker(ref), **kw)


def _persistent_policy():
    return idp.ReleasePolicy(default=idp.PolicyEntry(nameid_format=core.NAMEID_PERSISTENT))


# --------------------------------------------------------------------------- #
# check_request
# --------------------------------------------------------------------------- #

def test_check_request_asks_to_authenticate_and_the_response_is_signed(rsa_keypair):
    engine, ref = _engine(rsa_keypair)
    params = _params()

    disposition = engine.check_request(params)
    assert disposition.kind == "authenticate"
    assert [m.class_ref for m in disposition.methods] == [core.AUTHN_CONTEXT_PASSWORD]
    assert disposition.session is None and disposition.denial is None

    outcome = engine.create_authn_response(params, _subject(ref))
    assert outcome.is_issued and outcome.denied is None and outcome.denial is None
    issued = outcome.issued
    assert "SignatureValue" in issued.xml and outcome.xml == issued.xml
    assert 'InResponseTo="_req1"' in issued.xml
    assert issued.assertion_id and issued.response_id
    assert issued.released_attribute_names == ["mail"]
    assert issued.not_on_or_after.tzinfo is not None


def test_is_passive_without_a_session_is_a_signed_denial(rsa_keypair):
    engine, _ = _engine(rsa_keypair)
    params = _params(_request_xml(attrs='IsPassive="true"'))

    disposition = engine.check_request(params)
    assert disposition.kind == "deny"
    assert disposition.denial == idp.Denial.NO_PASSIVE

    denied = engine.create_denial_response(params, disposition.denial)
    assert "NoPassive" in denied.xml and "SignatureValue" in denied.xml
    assert denied.response_id


def test_an_established_session_is_reused_unless_force_authn_defeats_it(rsa_keypair):
    engine, ref = _engine(rsa_keypair)
    session = idp.EstablishedSession(
        "alice",
        idp.AuthnMethodRef.broker(ref),
        datetime.now(timezone.utc) - timedelta(minutes=5),
        "sess-1",
    )

    reuse = engine.check_request(_params(), session)
    assert reuse.kind == "reuse_session"
    assert reuse.session.session_index == "sess-1" and reuse.session.subject_id == "alice"

    forced = engine.check_request(_params(_request_xml(attrs='ForceAuthn="true"')), session)
    assert forced.kind == "authenticate"


def test_a_naive_datetime_is_rejected(rsa_keypair):
    _, ref = _engine(rsa_keypair)
    with pytest.raises(Exception):
        idp.EstablishedSession("alice", idp.AuthnMethodRef.broker(ref), datetime(2026, 1, 1), "s")


# --------------------------------------------------------------------------- #
# create_authn_response
# --------------------------------------------------------------------------- #

def test_a_persistent_nameid_is_stable_and_resolves_to_the_user(rsa_keypair):
    idents = idp.IdentDb(IDP)
    engine, ref = _engine(rsa_keypair, policy=_persistent_policy(), idents=idents)
    params = _params()

    first = engine.create_authn_response(params, _subject(ref)).issued.name_id
    second = engine.create_authn_response(params, _subject(ref)).issued.name_id
    assert first.format == core.NAMEID_PERSISTENT
    assert first.value == second.value
    assert idents.find_local_id(first) == "alice"


def test_an_overlong_requested_format_is_denied_and_nothing_is_stored(rsa_keypair):
    idents = idp.IdentDb(IDP)
    engine, ref = _engine(rsa_keypair, idents=idents)
    long_format = "urn:example:" + "a" * 300
    policy = f'<samlp:NameIDPolicy Format="{long_format}" AllowCreate="true"/>'
    params = _params(_request_xml(policy=policy))

    outcome = engine.create_authn_response(params, _subject(ref))
    assert not outcome.is_issued and outcome.issued is None
    assert outcome.denial == idp.Denial.INVALID_NAME_ID_POLICY
    assert "SignatureValue" in outcome.denied.xml
    assert idents.name_ids_for("alice") == []


def test_transient_nameids_resolve_only_when_persist_transient_is_set(rsa_keypair):
    for persist, expected in ((False, None), (True, "alice")):
        idents = idp.IdentDb(IDP, persist_transient=persist)
        engine, ref = _engine(rsa_keypair, idents=idents)
        name_id = engine.create_authn_response(_params(), _subject(ref)).issued.name_id
        assert name_id.format == core.NAMEID_TRANSIENT
        assert idents.find_local_id(name_id) == expected


def test_a_store_outage_is_an_exception_not_a_denial(rsa_keypair):
    class BrokenStore:
        def __getattr__(self, name):
            def fail(*a, **k):
                raise RuntimeError("backend down")
            return fail

    idents = idp.IdentDb(IDP, store=BrokenStore())
    engine, ref = _engine(rsa_keypair, policy=_persistent_policy(), idents=idents)
    with pytest.raises(pygamlastan.SamlStoreError, match="backend down"):
        engine.create_authn_response(_params(), _subject(ref))


def test_an_unknown_broker_reference_is_a_configuration_error(rsa_keypair):
    engine, _ = _engine(rsa_keypair)
    with pytest.raises(pygamlastan.SamlProfileError):
        engine.create_authn_response(_params(), _subject("not-registered"))


def test_an_inline_method_needs_no_broker_registration(rsa_keypair):
    engine, _ = _engine(rsa_keypair)
    subject = idp.AuthenticatedSubject(
        "alice", [], idp.AuthnMethodRef.inline(core.AUTHN_CONTEXT_PASSWORD, "https://upstream.example")
    )
    outcome = engine.create_authn_response(_params(), subject)
    assert outcome.is_issued
    assert "https://upstream.example" in outcome.xml  # AuthenticatingAuthority


def test_response_params_refuse_another_sps_metadata(rsa_keypair):
    other = SP_METADATA.replace(SP, "https://other.example.org/sp")
    with pytest.raises(pygamlastan.SamlProfileError):
        _params(sp_metadata=other)


# --------------------------------------------------------------------------- #
# Attribute release
# --------------------------------------------------------------------------- #

def _two_attributes():
    return [
        core.Attribute("mail", values=["alice@example.org"]),
        core.Attribute("displayName", values=["Alice"]),
    ]


def _released(engine, ref):
    subject = _subject(ref, attributes=_two_attributes())
    return sorted(engine.create_authn_response(_params(), subject).issued.released_attribute_names)


def test_with_no_rule_everything_supplied_is_released_and_restrictions_narrow(rsa_keypair):
    # The default follows pysaml2: the policy only narrows.
    engine, ref = _engine(rsa_keypair)
    assert _released(engine, ref) == ["displayName", "mail"]

    restricted = idp.ReleasePolicy(
        default=idp.PolicyEntry(attribute_restrictions=[("mail", None)])
    )
    engine, ref = _engine(rsa_keypair, policy=restricted)
    assert _released(engine, ref) == ["mail"]


def test_pass_through_ignores_the_policy_and_unknown_modes_are_rejected(rsa_keypair):
    restricted = idp.ReleasePolicy(
        default=idp.PolicyEntry(attribute_restrictions=[("mail", None)])
    )
    engine, ref = _engine(rsa_keypair, policy=restricted, release="pass_through")
    assert _released(engine, ref) == ["displayName", "mail"]

    with pytest.raises(ValueError, match="unknown release mode"):
        _engine(rsa_keypair, release="everything")


# --------------------------------------------------------------------------- #
# Request data the application needs
# --------------------------------------------------------------------------- #

def test_the_requested_subject_is_readable():
    subject = (
        '<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">'
        "alice-eppn</saml:NameID></saml:Subject>"
    )
    req = xml.parse_authn_request(_request_xml(subject=subject))
    assert req.has_requested_subject()
    assert req.requested_subject_name_id().value == "alice-eppn"

    plain = xml.parse_authn_request(_request_xml())
    assert not plain.has_requested_subject()
    assert plain.requested_subject_name_id() is None


def test_processed_request_exposes_the_nameid_policy_facts():
    with_policy = _params(
        _request_xml(policy='<samlp:NameIDPolicy SPNameQualifier="x" AllowCreate="true"/>')
    ).processed
    assert with_policy.has_name_id_policy
    assert with_policy.requested_sp_name_qualifier == "x"
    assert with_policy.requested_authn_context_decl_refs == []

    without = _params().processed
    assert not without.has_name_id_policy
    assert without.requested_sp_name_qualifier is None


def test_denial_members_are_comparable_and_hashable():
    assert idp.Denial.NO_PASSIVE == idp.Denial.NO_PASSIVE
    assert idp.Denial.NO_PASSIVE != idp.Denial.CANCELLED
    assert len({idp.Denial.AUTHN_FAILED, idp.Denial.AUTHN_FAILED, idp.Denial.CANCELLED}) == 2
