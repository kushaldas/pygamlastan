from datetime import datetime
from collections.abc import Callable, Iterable
from typing import Literal, Protocol

from .core import Assertion, Attribute, NameId, NameIdPolicy, RequestedAuthnContext
from .crypto import SamlSigner, SigningPreference
from .metadata import EntityDescriptor
from .profiles import ProcessedAuthnRequest

ISSUABLE_NAMEID_FORMATS: list[str]
MAX_NAMEID_FORMAT_LEN: int
COCO_V1: str
COCO_V2: str
REFEDS_RESEARCH_AND_SCHOLARSHIP: str
INCOMMON_RESEARCH_AND_SCHOLARSHIP: str
MYACADEMICID_ESI: str
REFEDS_PERSONALIZED: str
REFEDS_PSEUDONYMOUS: str
REFEDS_ANONYMOUS: str
AT_EGOV_PVP2: str
AT_EGOV_PVP2_CHARGE: str
ENTITY_CATEGORY_ATTR: str
SUBJECT_ID_ATTR: str
PAIRWISE_ID_ATTR: str
SUBJECT_ID_REQ_ATTR: str

class IdentityStore(Protocol):
    """Record-shaped NameID backend: one record per (user, NameID).

    The backend must enforce two unique constraints: the NameID value is unique
    across all records, and among durable records (every format except
    transient) ``(user, sp_name_qualifier, name_qualifier, format)`` is unique.
    A record with no ``format`` counts as ``unspecified``.

    ``replace`` updates a record in place for its owner and must never move a
    record to another user: raise ``NameIdValueTaken`` for a value another user
    holds (a reassigned value would let the new user log in as the old one at
    every SP that has seen it).

    The binding does not trust what the backend returns: a record from
    ``find_durable`` or ``get_or_insert_durable`` must be the durable slot asked
    for, and ``user_for(record.value)`` must name the same user, otherwise
    ``SamlStoreError`` is raised and the record is not used. So ``user_for`` must
    see the backend's own writes (read-your-writes), not a lagging replica.

    Raise ``NameIdValueTaken`` / ``NameIdDurableExists`` for a conflict. Any
    other exception is a backend failure and surfaces as ``SamlStoreError``:
    never return "no record" for a backend that could not answer.
    Optionally define ``find_durable(user_id, sp_name_qualifier, name_qualifier,
    format) -> NameId | None`` to push that lookup down to an index, and
    ``find(user_id, format, sp_name_qualifier, name_qualifier, sp_provided_id)
    -> Iterable[NameId]`` to push down ``IdentDb.find_nameid`` (``None`` means
    unconstrained; a field that is set must equal the record's exactly, so a
    record without it does not match). Each record ``find`` returns must satisfy
    the filter and belong to ``user_id``, or ``SamlStoreError`` is raised.
    """
    def for_user(self, user_id: str) -> Iterable[NameId]: ...
    def user_for(self, value: str) -> str | None: ...
    def get_or_insert_durable(self, user_id: str, candidate: NameId) -> NameId: ...
    def insert(self, user_id: str, name_id: NameId) -> None: ...
    def replace(self, user_id: str, name_id: NameId) -> None: ...
    def remove(self, value: str) -> None: ...
    def remove_all(self, user_id: str) -> None: ...

class KeyValueStore(Protocol):
    """Cache for ``Eptid``: issued values are remembered so a later change of
    secret or digest cannot change what an SP already knows. The keys are
    ``eptid:<idp>__<sp>__<user>`` and the values ``idp!sp!hash`` strings. Any
    exception is a backend failure and surfaces as ``SamlStoreError``; never
    return ``None`` for a backend that could not answer."""
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str) -> None: ...
    def remove(self, key: str) -> None: ...

class Eptid:
    def __init__(
        self,
        secret: str,
        digest: Literal["sha256", "pysaml2-md5"] = ...,
        allow_legacy_md5: bool = ...,
        store: KeyValueStore | None = ...,
    ) -> None: ...
    def get(self, idp_entity_id: str, sp_entity_id: str, user_id: str) -> str: ...
    def name_id(self, idp_entity_id: str, sp_entity_id: str, user_id: str) -> NameId: ...
    def attribute(self, idp_entity_id: str, sp_entity_id: str, user_id: str) -> Attribute: ...

class AuthnMethod:
    @property
    def class_ref(self) -> str: ...
    @property
    def method(self) -> str: ...
    @property
    def level(self) -> int: ...
    @property
    def authn_authority(self) -> str | None: ...
    @property
    def reference(self) -> str: ...

class AuthnBroker:
    def __init__(self, allow_exact_level_matching: bool = ...) -> None: ...
    def is_empty(self) -> bool: ...
    def add(self, class_ref: str, method: str, level: int, authn_authority: str | None = ...) -> str: ...
    def get_by_class_ref(self, class_ref: str) -> AuthnMethod | None: ...
    def pick(self, requested: RequestedAuthnContext | None = ...) -> list[AuthnMethod]: ...

class InMemoryAssertionStore:
    def __init__(self) -> None: ...
    def store_assertion(self, assertion: Assertion) -> None: ...
    def get_assertion(self, assertion_id: str) -> Assertion | None: ...
    def assertions_for_subject(self, name_id_value: str) -> list[Assertion]: ...
    def remove_assertion(self, assertion_id: str) -> None: ...

class IdentDb:
    def __init__(
        self,
        idp_entity_id: str,
        store: IdentityStore | None = ...,
        domain: str | None = ...,
        persist_transient: bool = ...,
    ) -> None: ...
    def store(self, user_id: str, name_id: NameId) -> None: ...
    def find_local_id(self, name_id: NameId) -> str | None: ...
    def find_nameid(
        self,
        user_id: str,
        format: str | None = ...,
        sp_name_qualifier: str | None = ...,
        name_qualifier: str | None = ...,
        sp_provided_id: str | None = ...,
    ) -> list[NameId]: ...
    def name_ids_for(self, user_id: str) -> list[NameId]: ...
    def match_local_id(
        self,
        user_id: str,
        sp_name_qualifier: str | None = ...,
        name_qualifier: str | None = ...,
    ) -> NameId | None: ...
    def transient_nameid(self, user_id: str, sp_name_qualifier: str | None = ...) -> NameId: ...
    def persistent_nameid(self, user_id: str, sp_name_qualifier: str | None = ...) -> NameId: ...
    def construct_nameid(
        self,
        user_id: str,
        sp_entity_id: str,
        name_id_policy: NameIdPolicy | None = ...,
        default_format: str | None = ...,
    ) -> NameId: ...
    def manage_name_id_new_id(self, name_id: NameId, new_id: str) -> NameId: ...
    def manage_name_id_terminate(self, name_id: NameId) -> NameId: ...
    def handle_name_id_mapping_request(
        self, name_id: NameId, name_id_policy: NameIdPolicy
    ) -> NameId: ...
    def remove_remote(self, name_id: NameId) -> None: ...
    def remove_local(self, user_id: str) -> None: ...

class EntityCategoryRule:
    def __init__(
        self,
        categories: list[str],
        attributes: list[str],
        conflicts: list[str] | None = ...,
        only_required: bool = ...,
    ) -> None: ...
    @property
    def categories(self) -> list[str]: ...
    @property
    def attributes(self) -> list[str]: ...
    @property
    def conflicts(self) -> list[str]: ...
    @property
    def only_required(self) -> bool: ...

class EntityCategoryPolicy:
    def __init__(
        self,
        name: str,
        rules: list[EntityCategoryRule] | None = ...,
        extend: str | None = ...,
    ) -> None: ...
    @staticmethod
    def shipped(name: str) -> EntityCategoryPolicy: ...
    @property
    def name(self) -> str: ...

class SignTargets:
    def __init__(
        self, response: bool = ..., assertion: bool = ..., on_demand: bool = ...
    ) -> None: ...
    @property
    def response(self) -> bool: ...
    @property
    def assertion(self) -> bool: ...
    @property
    def on_demand(self) -> bool: ...
    def resolve(self, sp_wants_assertions_signed: bool) -> ResolvedSignTargets: ...

class ResolvedSignTargets:
    @property
    def sign_response(self) -> bool: ...
    @property
    def sign_assertion(self) -> bool: ...

class PolicyEntry:
    def __init__(
        self,
        nameid_format: str | None = ...,
        name_form: str | None = ...,
        lifetime_seconds: int | None = ...,
        sign: SignTargets | None = ...,
        fail_on_missing_requested: bool | None = ...,
        entity_categories: list[str] | None = ...,
        owned_entity_categories: list[EntityCategoryPolicy] | None = ...,
        attribute_restrictions: list[tuple[str, list[str] | None]] | None = ...,
        session_lifetime_seconds: int | None = ...,
        supported_nameid_formats: list[str] | None = ...,
        signing_preference: SigningPreference | None = ...,
        deny_unconfigured_release: bool | None = ...,
    ) -> None: ...

class ReleasePolicy:
    def __init__(self, default: PolicyEntry | None = ...) -> None: ...
    def insert(self, sp_entity_id: str, entry: PolicyEntry) -> None: ...
    def set_registration_authority(
        self, sp_entity_id: str, registration_authority: str
    ) -> None: ...
    def register_sp_metadata(self, entity: EntityDescriptor) -> None: ...
    def nameid_format(self, sp_entity_id: str) -> str: ...
    def name_form(self, sp_entity_id: str) -> str: ...
    def lifetime_seconds(self, sp_entity_id: str) -> int: ...
    def not_on_or_after(self, sp_entity_id: str, now: datetime) -> datetime: ...
    def sign(self, sp_entity_id: str) -> SignTargets: ...
    def fail_on_missing_requested(self, sp_entity_id: str) -> bool: ...
    def session_lifetime_seconds(self, sp_entity_id: str) -> int: ...
    def supports_nameid_format(self, sp_entity_id: str, format: str) -> bool: ...
    def deny_unconfigured_release(self, sp_entity_id: str) -> bool: ...
    def signing_preference(self, sp_entity_id: str) -> SigningPreference: ...
    def filter(
        self,
        attributes: list[Attribute],
        sp_entity_id: str,
        sp_entity_categories: list[str] | None = ...,
        required: list[Attribute] | None = ...,
        optional: list[Attribute] | None = ...,
        subject_id_req: str = ...,
    ) -> list[Attribute]: ...

class Denial:
    """Why a request is refused with a signed SAML protocol error."""
    NO_PASSIVE: Denial
    NO_AUTHN_CONTEXT: Denial
    INVALID_NAME_ID_POLICY: Denial
    NAME_ID_CREATION_NOT_ALLOWED: Denial
    MISSING_REQUIRED_ATTRIBUTES: Denial
    INVALID_ATTRIBUTE_CONSUMING_SERVICE_INDEX: Denial
    AUTHN_FAILED: Denial
    CANCELLED: Denial

class AuthnMethodRef:
    """Which authentication method ran: a class ref given directly, or a method
    registered in the ``AuthnBroker``."""
    @staticmethod
    def inline(class_ref: str, authn_authority: str | None = ...) -> AuthnMethodRef: ...
    @staticmethod
    def broker(reference: str) -> AuthnMethodRef: ...
    @property
    def kind(self) -> Literal["inline", "broker"]: ...
    @property
    def class_ref(self) -> str | None: ...
    @property
    def authn_authority(self) -> str | None: ...
    @property
    def reference(self) -> str | None: ...

class AuthenticatedSubject:
    """The authenticated subject: identifier, raw (unfiltered) attributes, the
    method that ran, when (timezone-aware; ``None`` means now) and the session
    index."""
    def __init__(
        self,
        subject_id: str,
        attributes: list[Attribute],
        authn_method: AuthnMethodRef,
        authn_instant: datetime | None = ...,
        session_index: str | None = ...,
    ) -> None: ...
    @property
    def subject_id(self) -> str: ...
    @property
    def attributes(self) -> list[Attribute]: ...
    @property
    def authn_method(self) -> AuthnMethodRef: ...
    @property
    def authn_instant(self) -> datetime | None: ...
    @property
    def session_index(self) -> str | None: ...

class EstablishedSession:
    """An SSO session the application already has for the browser."""
    def __init__(
        self,
        subject_id: str,
        authn_method: AuthnMethodRef,
        authn_instant: datetime,
        session_index: str,
    ) -> None: ...
    @property
    def subject_id(self) -> str: ...
    @property
    def authn_method(self) -> AuthnMethodRef: ...
    @property
    def authn_instant(self) -> datetime: ...
    @property
    def session_index(self) -> str: ...

class ResponseParams:
    """A processed AuthnRequest bound to the trusted metadata of its SP.

    Raises ``SamlProfileError`` if ``entity`` is not the SP the request was
    validated for, or has no SAML 2.0 SP role."""
    def __init__(self, processed: ProcessedAuthnRequest, entity: EntityDescriptor) -> None: ...
    @property
    def processed(self) -> ProcessedAuthnRequest: ...

class Disposition:
    """What ``ResponseEngine.check_request`` decided."""
    @property
    def kind(self) -> Literal["reuse_session", "authenticate", "deny"]: ...
    @property
    def session(self) -> EstablishedSession | None: ...
    @property
    def methods(self) -> list[AuthnMethod]: ...
    @property
    def denial(self) -> Denial | None: ...

class IssuedResponse:
    """A signed successful response with the identifiers an audit log needs."""
    @property
    def xml(self) -> str: ...
    @property
    def response_id(self) -> str: ...
    @property
    def assertion_id(self) -> str | None: ...
    @property
    def name_id(self) -> NameId: ...
    @property
    def session_index(self) -> str | None: ...
    @property
    def not_on_or_after(self) -> datetime: ...
    @property
    def released_attribute_names(self) -> list[str]: ...

class DeniedResponse:
    """A signed protocol error response: no assertion, subject or session."""
    @property
    def xml(self) -> str: ...
    @property
    def response_id(self) -> str: ...

class ResponseOutcome:
    @property
    def is_issued(self) -> bool: ...
    @property
    def issued(self) -> IssuedResponse | None: ...
    @property
    def denied(self) -> DeniedResponse | None: ...
    @property
    def denial(self) -> Denial | None: ...
    @property
    def xml(self) -> str: ...

class AssertionStore(Protocol):
    """Where the response engine records issued assertions, so back-channel
    queries and logout can find them. Assertions cross as ``core.Assertion``.
    Any exception is a backend failure and surfaces as ``SamlStoreError``: never
    return ``None`` / an empty list for a backend that could not answer.

    The engine itself only calls ``store_assertion``; the other three serve the
    back-channel query responders and your own logout code (pysaml2
    ``remove_authn_statements`` is ``assertions_for_subject`` then
    ``remove_assertion``)."""
    def store_assertion(self, assertion: Assertion) -> None: ...
    def get_assertion(self, assertion_id: str) -> Assertion | None: ...
    def assertions_for_subject(self, name_id_value: str) -> Iterable[Assertion]: ...
    def remove_assertion(self, assertion_id: str) -> None: ...

class ResponseEngine:
    """The IdP response engine. ``release`` is ``"policy"`` (filter through the
    ``ReleasePolicy``) or ``"pass_through"`` (release what the application
    supplied). ``cert_der_b64`` is the signing certificate, base64 DER."""
    def __init__(
        self,
        idp_entity_id: str,
        policy: ReleasePolicy,
        idents: IdentDb,
        broker: AuthnBroker,
        signer: SamlSigner,
        cert_der_b64: str,
        assertions: InMemoryAssertionStore | AssertionStore | None = ...,
        release: Literal["policy", "pass_through"] = ...,
    ) -> None: ...
    def check_request(
        self, params: ResponseParams, session: EstablishedSession | None = ...
    ) -> Disposition: ...
    def create_authn_response(
        self, params: ResponseParams, subject: AuthenticatedSubject
    ) -> ResponseOutcome: ...
    def create_denial_response(self, params: ResponseParams, denial: Denial) -> DeniedResponse: ...

STORE_CONFORMANCE_CHECKS: list[str]

def check_store_conformance(new_store: Callable[[], IdentityStore], threads: int = ...) -> None:
    """Check that an ``IdentityStore`` honours the contract the response engine
    relies on. ``new_store`` returns a fresh, empty store on every call. Raises
    ``StoreConformanceError`` (``.check``, ``.message``) on the first violation."""
    ...

def check_store_conformance_one(
    name: str, new_store: Callable[[], IdentityStore], threads: int = ...
) -> None:
    """Run one check, by name (see ``STORE_CONFORMANCE_CHECKS``)."""
    ...

def releasable_attributes(
    policies: list[EntityCategoryPolicy],
    sp_entity_categories: list[str],
    required_local_names: list[str] | None = ...,
) -> list[str]: ...
def subject_id_req_from_metadata(values: list[str]) -> str: ...
def code_name_id(name_id: NameId) -> str: ...
def decode_name_id(coded: str) -> NameId: ...
