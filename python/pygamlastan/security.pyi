from datetime import datetime
from typing import Any, Protocol

from .core import Response

class ReplayCacheProtocol(Protocol):
    def check_and_insert(self, id: str, expiry: datetime) -> bool: ...
    def cleanup(self) -> None: ...

class PersistentIdStoreProtocol(Protocol):
    def check_and_record(self, name_id: str, sp_entity_id: str, principal: str) -> bool: ...

class SecurityConfig:
    def __init__(self) -> None: ...
    @staticmethod
    def permissive() -> SecurityConfig: ...
    @staticmethod
    def strict() -> SecurityConfig: ...
    clock_skew_seconds: int
    require_signed_assertions: bool
    require_signed_responses: bool
    max_assertion_age_seconds: int
    verify_destination: bool
    verify_recipient: bool
    require_encrypted_assertions: bool
    reject_signatures_with_ds_object: bool
    enforce_persistent_id_uniqueness: bool
    sanitize_relay_state: bool
    require_integrity_with_cbc: bool
    check_client_address: bool

class ValidationCheck:
    @property
    def check_number(self) -> int: ...
    @property
    def check_name(self) -> str: ...
    @property
    def passed(self) -> bool: ...
    @property
    def detail(self) -> str | None: ...

class ValidationResult:
    def is_valid(self) -> bool: ...
    def __bool__(self) -> bool: ...
    def total_checks(self) -> int: ...
    @property
    def checks(self) -> list[ValidationCheck]: ...
    def failures(self) -> list[ValidationCheck]: ...

class InMemoryReplayCache:
    def __init__(self) -> None: ...
    def check_and_insert(self, id: str, expiry: datetime) -> bool: ...
    def cleanup(self) -> None: ...
    def __len__(self) -> int: ...

def validate_response(
    response: Response,
    config: SecurityConfig,
    received_url: str,
    expected_idp_entity_id: str,
    sp_entity_id: str,
    acs_url: str,
    expected_request_id: str | None = ...,
    client_address: str | None = ...,
    relay_state: str | None = ...,
    response_signature_verified: bool | None = ...,
    verified_signed_ids: list[str] | None = ...,
    current_proxy_depth: int = ...,
    now: datetime | None = ...,
    replay_cache: Any | None = ...,
    persistent_id_store: Any | None = ...,
    unsafe_no_replay_cache: bool = ...,
    unsafe_no_persistent_id_store: bool = ...,
) -> ValidationResult: ...
