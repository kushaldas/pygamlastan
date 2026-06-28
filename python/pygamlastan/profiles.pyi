from datetime import datetime

from .core import Attribute, AuthnRequest, NameId, Response
from .crypto import SamlVerifier
from .metadata import EntityDescriptor
from .security import PersistentIdStoreProtocol, ReplayCacheProtocol, SecurityConfig

class AuthnRequestOptions:
    def __init__(
        self,
        sp_entity_id: str,
        acs_url: str | None = ...,
        acs_index: int | None = ...,
        protocol_binding: str | None = ...,
        force_authn: bool | None = ...,
        is_passive: bool | None = ...,
        name_id_format: str | None = ...,
        allow_create: bool = ...,
        sp_name_qualifier: str | None = ...,
        authn_context_class_refs: list[str] | None = ...,
        authn_context_comparison: str | None = ...,
        provider_name: str | None = ...,
        destination: str | None = ...,
        proxy_count: int | None = ...,
        requester_ids: list[str] | None = ...,
        attribute_consuming_service_index: int | None = ...,
        extensions: str | None = ...,
    ) -> None: ...

class AuthnResult:
    @property
    def name_id(self) -> str: ...
    @property
    def name_id_format(self) -> str | None: ...
    @property
    def name_qualifier(self) -> str | None: ...
    @property
    def sp_name_qualifier(self) -> str | None: ...
    @property
    def session_index(self) -> str | None: ...
    @property
    def session_not_on_or_after(self) -> datetime | None: ...
    @property
    def authn_instant(self) -> datetime: ...
    @property
    def authn_context_class_ref(self) -> str | None: ...
    @property
    def authenticating_authorities(self) -> list[str]: ...
    @property
    def attributes(self) -> list[Attribute]: ...
    def attributes_dict(self) -> dict[str, list[str]]: ...
    @property
    def idp_entity_id(self) -> str: ...
    @property
    def assertion_id(self) -> str: ...
    @property
    def response_id(self) -> str: ...

class ProcessedAuthnRequest:
    @property
    def request_id(self) -> str: ...
    @property
    def sp_entity_id(self) -> str: ...
    @property
    def acs_url(self) -> str: ...
    @property
    def acs_binding(self) -> str: ...
    @property
    def force_authn(self) -> bool: ...
    @property
    def is_passive(self) -> bool: ...
    @property
    def requested_name_id_format(self) -> str | None: ...
    @property
    def allow_create(self) -> bool: ...
    @property
    def requested_authn_context_class_refs(self) -> list[str]: ...
    @property
    def attribute_consuming_service_index(self) -> int | None: ...

class ResponseOptions:
    def __init__(
        self,
        idp_entity_id: str,
        sp_entity_id: str,
        acs_url: str,
        assertion_lifetime_seconds: int = ...,
        in_response_to: str | None = ...,
        session_index: str | None = ...,
        session_not_on_or_after: datetime | None = ...,
        authn_context_class_ref: str | None = ...,
        client_address: str | None = ...,
        attributes: list[Attribute] | None = ...,
    ) -> None: ...

class InMemorySessionStore:
    def __init__(self) -> None: ...
    def __len__(self) -> int: ...
    def destroy_session(self, session_index: str) -> bool: ...
    def cleanup_expired(self) -> None: ...

def create_authn_request(options: AuthnRequestOptions) -> AuthnRequest: ...
def process_response(
    response: Response,
    config: SecurityConfig,
    sp_entity_id: str,
    acs_url: str,
    expected_idp_entity_id: str,
    expected_request_id: str | None = ...,
    verified_signed_ids: list[str] | None = ...,
    now: datetime | None = ...,
    replay_cache: ReplayCacheProtocol | None = ...,
    persistent_id_store: PersistentIdStoreProtocol | None = ...,
    unsafe_no_replay_cache: bool = ...,
    unsafe_no_persistent_id_store: bool = ...,
) -> AuthnResult: ...
def process_response_verified(
    response_xml: str,
    verifier: SamlVerifier,
    config: SecurityConfig,
    sp_entity_id: str,
    acs_url: str,
    expected_idp_entity_id: str,
    expected_request_id: str | None = ...,
    now: datetime | None = ...,
    replay_cache: ReplayCacheProtocol | None = ...,
    persistent_id_store: PersistentIdStoreProtocol | None = ...,
    unsafe_no_replay_cache: bool = ...,
    unsafe_no_persistent_id_store: bool = ...,
) -> AuthnResult: ...
def process_authn_request(
    request: AuthnRequest,
    sp_metadata: EntityDescriptor | None = ...,
    unsafe_allow_missing_metadata: bool = ...,
) -> ProcessedAuthnRequest: ...
def create_response(
    options: ResponseOptions,
    principal_name_id: NameId,
    now: datetime | None = ...,
    authn_instant: datetime | None = ...,
) -> Response: ...
def create_unsolicited_response(
    idp_entity_id: str,
    sp_entity_id: str,
    acs_url: str,
    principal_name_id: NameId,
    attributes: list[Attribute] | None = ...,
    authn_context_class_ref: str | None = ...,
    assertion_lifetime_seconds: int = ...,
    session_index: str | None = ...,
    session_not_on_or_after: datetime | None = ...,
    client_address: str | None = ...,
    now: datetime | None = ...,
    authn_instant: datetime | None = ...,
) -> Response: ...
def create_error_response(
    idp_entity_id: str,
    acs_url: str,
    status_code: str,
    status_message: str | None = ...,
    in_response_to: str | None = ...,
    now: datetime | None = ...,
) -> Response: ...
