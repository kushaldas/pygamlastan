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


def _request_xml(attrs="", subject="", policy="", context=""):
    return (
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req1" Version="2.0" '
        f'IssueInstant="2026-06-24T10:00:00Z" Destination="{IDP}/sso" '
        f'AssertionConsumerServiceURL="{ACS}" '
        f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {attrs}>'
        f"<saml:Issuer>{SP}</saml:Issuer>{subject}{policy}{context}</samlp:AuthnRequest>"
    )


def _params(request_xml=None, sp_metadata=SP_METADATA):
    req = xml.parse_authn_request(request_xml or _request_xml())
    entity = metadata.parse_entity(SP_METADATA)
    processed = profiles.process_authn_request(req, entity)
    return idp.ResponseParams(processed, metadata.parse_entity(sp_metadata))


def _engine(
    rsa_keypair, *, policy=None, idents=None, assertions=None, release="policy", empty_broker=False
):
    priv, _cert, cert_b64 = rsa_keypair
    broker = idp.AuthnBroker()
    ref = None if empty_broker else broker.add(core.AUTHN_CONTEXT_PASSWORD, "/login/password", 1)
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


# --------------------------------------------------------------------------- #
# The SAML 2.0 SP role is the one a request is held to
# --------------------------------------------------------------------------- #

def _two_role_metadata(*, legacy_first, saml2_requires_signed=True):
    """An SP with a legacy SAML 1.1 role (which does not require signed requests)
    and a SAML 2.0 role (which does, by default), in the order asked for."""
    legacy = (
        '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol" '
        'AuthnRequestsSigned="false">'
        '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post" '
        'Location="https://sp.example.org/legacy-acs" index="0" isDefault="true"/>'
        "</md:SPSSODescriptor>"
    )
    saml2 = (
        '<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'AuthnRequestsSigned="{str(saml2_requires_signed).lower()}">'
        '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        f'Location="{ACS}" index="0" isDefault="true"/>'
        "</md:SPSSODescriptor>"
    )
    roles = legacy + saml2 if legacy_first else saml2 + legacy
    return (
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{SP}">{roles}</md:EntityDescriptor>'
    )


@pytest.mark.parametrize("legacy_first", [True, False])
def test_an_unsigned_request_is_held_to_the_saml2_roles_signing_requirement(legacy_first):
    # The legacy role does not require signed requests; the SAML 2.0 role does. Which
    # role is listed first must not decide which requirement applies.
    entity = metadata.parse_entity(_two_role_metadata(legacy_first=legacy_first))
    req = xml.parse_authn_request(_request_xml())

    with pytest.raises(pygamlastan.SamlProfileError, match="signature"):
        profiles.process_authn_request(req, entity)
    # A verified signature satisfies it, and the ACS is the SAML 2.0 role's.
    processed = profiles.process_authn_request(req, entity, request_signature_verified=True)
    assert processed.acs_url == ACS


def test_the_saml2_role_alone_decides_whether_a_signature_is_required():
    entity = metadata.parse_entity(
        _two_role_metadata(legacy_first=False, saml2_requires_signed=False)
    )
    req = xml.parse_authn_request(_request_xml())
    assert profiles.process_authn_request(req, entity).acs_url == ACS


def test_metadata_with_no_saml2_sp_role_cannot_process_a_request():
    legacy_only = (
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'entityID="{SP}"><md:SPSSODescriptor '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol">'
        '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post" '
        f'Location="{ACS}" index="0"/></md:SPSSODescriptor></md:EntityDescriptor>'
    )
    entity = metadata.parse_entity(legacy_only)
    req = xml.parse_authn_request(_request_xml())
    with pytest.raises(pygamlastan.SamlProfileError, match="SAML 2.0 SPSSODescriptor"):
        profiles.process_authn_request(req, entity)


# --------------------------------------------------------------------------- #
# Lifetimes that cannot be added to a date
# --------------------------------------------------------------------------- #

LATEST = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


@pytest.mark.parametrize("knob", ["session_lifetime_seconds", "lifetime_seconds"])
@pytest.mark.parametrize(
    "seconds",
    [
        3 * 10**11,  # about 9 500 years: fine for chrono, but not an xs:dateTime
        10**13,  # past anything chrono holds: used to be a PanicException
        9_223_372_036_854_775,  # the longest duration PolicyEntry accepts
    ],
)
def test_a_lifetime_too_long_to_add_is_an_error_and_nothing_is_stored(rsa_keypair, knob, seconds):
    idents = idp.IdentDb(IDP)
    policy = idp.ReleasePolicy(
        default=idp.PolicyEntry(nameid_format=core.NAMEID_PERSISTENT, **{knob: seconds})
    )
    engine, ref = _engine(rsa_keypair, policy=policy, idents=idents)

    with pytest.raises(pygamlastan.SamlProfileError, match="years 0001-9999"):
        engine.create_authn_response(_params(), _subject(ref))
    assert idents.name_ids_for("alice") == []


def test_an_authn_instant_at_the_end_of_time_is_an_error_not_a_panic(rsa_keypair):
    engine, ref = _engine(rsa_keypair, policy=_persistent_policy())
    with pytest.raises(pygamlastan.SamlProfileError, match="years 0001-9999"):
        # The default session lifetime added to the last day Python can pass in.
        engine.create_authn_response(_params(), _subject(ref, authn_instant=LATEST))


def test_a_long_but_writable_lifetime_is_still_issued(rsa_keypair):
    policy = idp.ReleasePolicy(
        default=idp.PolicyEntry(session_lifetime_seconds=100 * 365 * 24 * 3600)
    )
    engine, ref = _engine(rsa_keypair, policy=policy)
    assert engine.create_authn_response(_params(), _subject(ref)).is_issued


def test_not_on_or_after_saturates_instead_of_panicking():
    now = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
    ordinary = idp.ReleasePolicy(default=idp.PolicyEntry(lifetime_seconds=300))
    assert ordinary.not_on_or_after(SP, now) == now + timedelta(seconds=300)
    for seconds in (3 * 10**11, 10**13, 9_223_372_036_854_775):
        policy = idp.ReleasePolicy(default=idp.PolicyEntry(lifetime_seconds=seconds))
        assert policy.not_on_or_after(SP, now) == LATEST


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


# --------------------------------------------------------------------------- #
# Policy and signing knobs
# --------------------------------------------------------------------------- #

def _context(comparison, class_ref):
    return (
        f'<samlp:RequestedAuthnContext Comparison="{comparison}">'
        f"<saml:AuthnContextClassRef>{class_ref}</saml:AuthnContextClassRef>"
        "</samlp:RequestedAuthnContext>"
    )


def _invented_format_request():
    policy = '<samlp:NameIDPolicy Format="urn:example:invented" AllowCreate="true"/>'
    return _params(_request_xml(policy=policy))


def test_an_invented_nameid_format_is_accepted_by_default_and_refused_when_listed(rsa_keypair):
    engine, ref = _engine(rsa_keypair)
    issued = engine.create_authn_response(_invented_format_request(), _subject(ref))
    assert issued.is_issued and issued.issued.name_id.format == "urn:example:invented"

    strict = idp.ReleasePolicy(
        default=idp.PolicyEntry(supported_nameid_formats=idp.ISSUABLE_NAMEID_FORMATS)
    )
    idents = idp.IdentDb(IDP)
    engine, ref = _engine(rsa_keypair, policy=strict, idents=idents)
    outcome = engine.create_authn_response(_invented_format_request(), _subject(ref))
    assert outcome.denial == idp.Denial.INVALID_NAME_ID_POLICY
    assert idents.name_ids_for("alice") == []


def test_supports_nameid_format_and_the_constants():
    assert idp.MAX_NAMEID_FORMAT_LEN == 256
    assert core.NAMEID_PERSISTENT in idp.ISSUABLE_NAMEID_FORMATS
    policy = idp.ReleasePolicy()
    assert policy.supports_nameid_format(SP, "urn:example:anything")
    assert not policy.supports_nameid_format(SP, "urn:example:" + "a" * idp.MAX_NAMEID_FORMAT_LEN)
    listed = idp.ReleasePolicy(
        default=idp.PolicyEntry(supported_nameid_formats=[core.NAMEID_PERSISTENT])
    )
    assert listed.supports_nameid_format(SP, core.NAMEID_PERSISTENT)
    assert not listed.supports_nameid_format(SP, "urn:example:anything")


def test_deny_unconfigured_release_fails_closed_and_a_rule_lifts_it(rsa_keypair):
    closed = idp.ReleasePolicy(default=idp.PolicyEntry(deny_unconfigured_release=True))
    assert closed.deny_unconfigured_release(SP)
    assert not idp.ReleasePolicy().deny_unconfigured_release(SP)
    engine, ref = _engine(rsa_keypair, policy=closed)
    assert _released(engine, ref) == []

    covered = idp.ReleasePolicy(
        default=idp.PolicyEntry(
            deny_unconfigured_release=True, attribute_restrictions=[("mail", None)]
        )
    )
    engine, ref = _engine(rsa_keypair, policy=covered)
    assert _released(engine, ref) == ["mail"]

    overridden = idp.ReleasePolicy(default=idp.PolicyEntry(deny_unconfigured_release=True))
    overridden.insert(SP, idp.PolicyEntry(deny_unconfigured_release=False))
    engine, ref = _engine(rsa_keypair, policy=overridden)
    assert _released(engine, ref) == ["displayName", "mail"]


def test_a_signing_preference_selects_the_algorithms(rsa_keypair):
    prefer = crypto.SigningPreference(
        [crypto.SignatureMethod.RSA_SHA512], [crypto.DigestMethod.SHA512]
    )
    policy = idp.ReleasePolicy(default=idp.PolicyEntry(signing_preference=prefer))
    engine, ref = _engine(rsa_keypair, policy=policy)
    xml_out = engine.create_authn_response(_params(), _subject(ref)).xml
    assert crypto.SignatureMethod.RSA_SHA512.uri in xml_out
    assert crypto.DigestMethod.SHA512.uri in xml_out
    assert crypto.SignatureMethod.RSA_SHA256.uri not in xml_out

    default_xml = _engine(rsa_keypair)[0].create_authn_response(_params(), _subject(ref)).xml
    assert crypto.SignatureMethod.RSA_SHA256.uri in default_xml


def test_signing_preference_resolution_only_chooses_among_your_entries():
    sha = crypto.SignatureMethod
    pref = crypto.SigningPreference(
        [sha.RSA_SHA512, sha.RSA_SHA384], [crypto.DigestMethod.SHA512, crypto.DigestMethod.SHA384]
    )
    chosen = pref.resolve([sha.RSA_SHA384.uri], [crypto.DigestMethod.SHA384.uri])
    assert chosen.signature == sha.RSA_SHA384 and chosen.digest == crypto.DigestMethod.SHA384
    # Nothing usable advertised: the first entry. A URI under the wrong element
    # does not count, and the SP cannot add an algorithm of its own.
    fallback = pref.resolve([crypto.DigestMethod.SHA384.uri, "urn:evil"], [sha.RSA_SHA384.uri])
    assert fallback.signature == sha.RSA_SHA512 and fallback.digest == crypto.DigestMethod.SHA512
    assert crypto.SigningPreference().resolve().signature is None


def test_weak_algorithms_are_not_representable():
    assert crypto.SignatureMethod.from_uri("http://www.w3.org/2000/09/xmldsig#rsa-sha1") is None
    assert crypto.DigestMethod.from_uri("http://www.w3.org/2000/09/xmldsig#sha1") is None
    uri = crypto.SignatureMethod.ECDSA_SHA256.uri
    assert crypto.SignatureMethod.from_uri(uri) == crypto.SignatureMethod.ECDSA_SHA256


def test_session_lifetime_limits_how_long_a_session_is_reused(rsa_keypair):
    short = idp.ReleasePolicy(default=idp.PolicyEntry(session_lifetime_seconds=60))
    assert short.session_lifetime_seconds(SP) == 60
    with pytest.raises(pygamlastan.SamlPolicyError):
        idp.PolicyEntry(session_lifetime_seconds=-1)

    engine, ref = _engine(rsa_keypair, policy=short)
    session = idp.EstablishedSession(
        "alice",
        idp.AuthnMethodRef.broker(ref),
        datetime.now(timezone.utc) - timedelta(minutes=5),
        "sess-1",
    )
    assert engine.check_request(_params(), session).kind == "authenticate"
    longer = _engine(rsa_keypair)[0]  # defaults to the one-hour assertion lifetime
    assert longer.check_request(_params(), session).kind == "reuse_session"


def test_an_empty_broker_defers_exact_requests_and_denies_the_rest(rsa_keypair):
    assert idp.AuthnBroker().is_empty()
    engine, _ = _engine(rsa_keypair, empty_broker=True)

    exact = engine.check_request(_params(_request_xml(context=_context("exact", "urn:example:acr"))))
    assert exact.kind == "authenticate" and exact.methods == []

    minimum = engine.check_request(
        _params(_request_xml(context=_context("minimum", "urn:example:acr")))
    )
    assert minimum.kind == "deny" and minimum.denial == idp.Denial.NO_AUTHN_CONTEXT

    # An inline method whose class ref matches literally can then be issued.
    subject = idp.AuthenticatedSubject("alice", [], idp.AuthnMethodRef.inline("urn:example:acr"))
    outcome = engine.create_authn_response(
        _params(_request_xml(context=_context("exact", "urn:example:acr"))), subject
    )
    assert outcome.is_issued


def test_exact_level_matching_is_opt_in():
    ppt = core.AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
    requested = xml.parse_authn_request(
        _request_xml(context=_context("exact", ppt))
    ).requested_authn_context

    def broker(flag):
        b = idp.AuthnBroker(allow_exact_level_matching=flag)
        b.add(core.AUTHN_CONTEXT_PASSWORD, "/login/password", 1)
        b.add(ppt, "/login/ppt", 1)
        return b

    assert [m.class_ref for m in broker(False).pick(requested)] == [ppt]
    assert sorted(m.class_ref for m in broker(True).pick(requested)) == sorted(
        [core.AUTHN_CONTEXT_PASSWORD, ppt]
    )
    assert not broker(False).is_empty()


# --------------------------------------------------------------------------- #
# Assertion stores
# --------------------------------------------------------------------------- #

class RecordingAssertionStore:
    def __init__(self):
        self.stored = []

    def store_assertion(self, assertion):
        self.stored.append(assertion)

    def get_assertion(self, assertion_id):
        return next((a for a in self.stored if a.id == assertion_id), None)

    def assertions_for_subject(self, name_id_value):
        return [
            a for a in self.stored
            if a.subject is not None and a.subject.name_id.value == name_id_value
        ]

    def remove_assertion(self, assertion_id):
        self.stored = [a for a in self.stored if a.id != assertion_id]


def test_a_python_assertion_store_records_what_is_issued(rsa_keypair):
    store = RecordingAssertionStore()
    engine, ref = _engine(rsa_keypair, assertions=store)
    issued = engine.create_authn_response(_params(), _subject(ref)).issued
    assert [a.id for a in store.stored] == [issued.assertion_id]
    assert store.assertions_for_subject(issued.name_id.value)[0].id == issued.assertion_id


def test_the_built_in_assertion_store_still_works(rsa_keypair):
    store = idp.InMemoryAssertionStore()
    engine, ref = _engine(rsa_keypair, assertions=store)
    issued = engine.create_authn_response(_params(), _subject(ref)).issued
    assert store.get_assertion(issued.assertion_id) is not None
    assert len(store.assertions_for_subject(issued.name_id.value)) == 1


def test_an_assertion_store_that_cannot_record_means_nothing_is_issued(rsa_keypair):
    class Down(RecordingAssertionStore):
        def store_assertion(self, assertion):
            raise RuntimeError("assertion db down")

    engine, ref = _engine(rsa_keypair, assertions=Down())
    with pytest.raises(pygamlastan.SamlStoreError, match="assertion db down"):
        engine.create_authn_response(_params(), _subject(ref))


def test_a_denial_stores_no_assertion(rsa_keypair):
    store = RecordingAssertionStore()
    engine, ref = _engine(rsa_keypair, assertions=store)
    long_format = "urn:example:" + "a" * 300
    policy = f'<samlp:NameIDPolicy Format="{long_format}" AllowCreate="true"/>'
    outcome = engine.create_authn_response(_params(_request_xml(policy=policy)), _subject(ref))
    assert not outcome.is_issued and store.stored == []


# --------------------------------------------------------------------------- #
# What the engine does not verify, recorded so it is not a surprise
# --------------------------------------------------------------------------- #

def test_an_inline_class_ref_is_the_applications_claim_and_is_never_verified(rsa_keypair):
    # For Comparison="exact" an inline class ref satisfies the request by matching
    # the request itself. An application that builds it from request data signs a
    # claim that was never established, so the docs say never to do that.
    strong = core.AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
    ctx = _context("exact", strong)
    echoed = idp.AuthenticatedSubject("alice", [], idp.AuthnMethodRef.inline(strong))

    engine, _ = _engine(rsa_keypair, empty_broker=True)
    outcome = engine.create_authn_response(_params(_request_xml(context=ctx)), echoed)
    assert outcome.is_issued and strong in outcome.xml

    # With a broker that registers only a weaker method, check_request refuses...
    engine, _ = _engine(rsa_keypair)
    assert engine.check_request(_params(_request_xml(context=ctx))).kind == "deny"
    # ...but create_authn_response alone does not stop an application that skips it
    # and echoes the request.
    assert engine.create_authn_response(_params(_request_xml(context=ctx)), echoed).is_issued


def test_authn_method_ref_describes_itself():
    inline = idp.AuthnMethodRef.inline("urn:example:acr", "https://upstream.example")
    assert (inline.kind, inline.class_ref, inline.reference) == ("inline", "urn:example:acr", None)
    assert inline.authn_authority == "https://upstream.example"
    assert "inline" in repr(inline) and "urn:example:acr" in repr(inline)

    broker = idp.AuthnMethodRef.broker("ref-1")
    assert (broker.kind, broker.reference, broker.class_ref) == ("broker", "ref-1", None)
    assert "ref-1" in repr(broker)


def test_a_broker_methods_authority_reaches_the_signed_assertion(rsa_keypair):
    priv, _cert, cert_b64 = rsa_keypair
    broker = idp.AuthnBroker()
    ref = broker.add(core.AUTHN_CONTEXT_PASSWORD, "/login", 1, "https://upstream.example/idp")
    engine = idp.ResponseEngine(
        IDP, idp.ReleasePolicy(), idp.IdentDb(IDP), broker,
        crypto.SamlSigner(crypto.KeysManager.build_idp(priv)), cert_b64,
    )
    outcome = engine.create_authn_response(_params(), _subject(ref))
    assert "AuthenticatingAuthority" in outcome.xml
    assert "https://upstream.example/idp" in outcome.xml


@pytest.mark.parametrize(
    "authority",
    [
        "not-a-uri",  # no scheme
        " https://ok.example",  # leading whitespace
        "https://ok.example /x",  # embedded whitespace
        "https://ok.example/\x00x",  # control character
        "https://ok.example/" + "a" * 1100,  # over 1024 bytes
    ],
)
def test_a_malformed_authenticating_authority_is_refused_before_anything_is_stored(
    rsa_keypair, authority
):
    idents = idp.IdentDb(IDP)
    assertions = idp.InMemoryAssertionStore()
    engine, _ = _engine(
        rsa_keypair, policy=_persistent_policy(), idents=idents, assertions=assertions
    )
    subject = idp.AuthenticatedSubject(
        "alice",
        [core.Attribute("mail", values=["alice@example.org"])],
        idp.AuthnMethodRef.inline(core.AUTHN_CONTEXT_PASSWORD, authority),
    )
    with pytest.raises(pygamlastan.SamlProfileError, match="authenticating authority"):
        engine.create_authn_response(_params(), subject)
    assert idents.name_ids_for("alice") == []
    assert assertions.assertions_for_subject("alice") == []


def test_markup_in_an_authenticating_authority_is_escaped_not_injected(rsa_keypair):
    # The validator checks the shape of a URI, not for markup: what keeps a payload from
    # becoming structure is the serializer's escaping. Pin that, so it stays true.
    engine, _ = _engine(rsa_keypair, policy=_persistent_policy())
    payload = "https://ok.example</saml:AuthenticatingAuthority><saml:AuthenticatingAuthority>evil"
    subject = idp.AuthenticatedSubject(
        "alice",
        [core.Attribute("mail", values=["alice@example.org"])],
        idp.AuthnMethodRef.inline(core.AUTHN_CONTEXT_PASSWORD, payload),
    )
    xml_out = engine.create_authn_response(_params(), subject).xml
    assert "<saml:AuthenticatingAuthority>evil" not in xml_out
    assert xml_out.count("<saml:AuthenticatingAuthority>") == 1


def test_an_encrypted_requested_subject_is_reported_but_not_readable():
    encrypted = (
        "<saml:Subject><saml:EncryptedID>"
        '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" '
        'Type="http://www.w3.org/2001/04/xmlenc#Element">'
        "<xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData>"
        "</xenc:EncryptedData></saml:EncryptedID></saml:Subject>"
    )
    req = xml.parse_authn_request(_request_xml(subject=encrypted))
    assert req.has_requested_subject()  # the SP did name a principal...
    assert req.requested_subject_name_id() is None  # ...which we cannot read
