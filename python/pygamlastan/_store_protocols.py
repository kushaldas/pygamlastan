"""Runtime versions of the store protocols that `pygamlastan.idp` documents.

The stub (`idp.pyi`) declares `IdentityStore`, `KeyValueStore` and `AssertionStore`
so a type checker knows what a backend must implement, but the extension itself
only duck-types the object it is given. Without these definitions
`from pygamlastan.idp import IdentityStore` type-checks and then raises
`ImportError`. They are attached to `pygamlastan.idp` by the package `__init__`.

They list the *required* methods only, so `isinstance(store, IdentityStore)` is true
for a minimal backend. The optional `find` / `find_durable` are not members; see the
`IdentityStore` documentation. Each is `runtime_checkable`, which checks that the
methods exist, not their signatures: run the conformance suites for that.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .core import Assertion, NameId


@runtime_checkable
class IdentityStore(Protocol):
    """Record-shaped NameID backend: one record per (user, NameID). See
    `pygamlastan.idp` for the contract, and run `idp.check_store_conformance`
    against your backend."""

    def for_user(self, user_id: str) -> Iterable[NameId]: ...
    def user_for(self, value: str) -> str | None: ...
    def get_or_insert_durable(self, user_id: str, candidate: NameId) -> NameId: ...
    def insert(self, user_id: str, name_id: NameId) -> None: ...
    def replace(self, user_id: str, name_id: NameId) -> None: ...
    def remove(self, value: str) -> None: ...
    def remove_all(self, user_id: str) -> None: ...


@runtime_checkable
class KeyValueStore(Protocol):
    """Cache for `Eptid`: issued values are remembered so a later change of secret
    or digest cannot change what an SP already knows. Run
    `idp.check_kv_conformance` against your backend."""

    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str) -> None: ...
    def remove(self, key: str) -> None: ...


@runtime_checkable
class AssertionStore(Protocol):
    """Where the response engine records issued assertions. Run
    `idp.check_assertion_store_conformance` against your backend."""

    def store_assertion(self, assertion: Assertion) -> None: ...
    def get_assertion(self, assertion_id: str) -> Assertion | None: ...
    def assertions_for_subject(self, name_id_value: str) -> Iterable[Assertion]: ...
    def remove_assertion(self, assertion_id: str) -> None: ...
