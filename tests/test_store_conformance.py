"""The `IdentityStore` conformance suite, driven from Python.

A missing unique index compiles fine and only misbehaves under load, so a
Python backend (Mongo, SQL) proves it honours the contract by passing this
suite against a real instance. These tests use in-process stores: a correct one
that must pass, and deliberately broken ones that must fail the right check.
"""

import threading
import time

import pytest

import pygamlastan
from pygamlastan import idp

TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"


class GoodStore:
    """A correct record-shaped store; one lock makes every method atomic."""

    def __init__(self):
        self.records = []  # (user_id, NameId)
        self.lock = threading.Lock()

    @staticmethod
    def _slot(n):
        fmt = n.format or UNSPECIFIED
        return None if fmt == TRANSIENT else (n.sp_name_qualifier, n.name_qualifier, fmt)

    def _owner(self, value):
        return next((u for u, n in self.records if n.value == value), None)

    def _durable_clash(self, user_id, n):
        slot = self._slot(n)
        return slot is not None and any(
            u == user_id and e.value != n.value and self._slot(e) == slot
            for u, e in self.records
        )

    def for_user(self, user_id):
        with self.lock:
            return [n for u, n in self.records if u == user_id]

    def user_for(self, value):
        with self.lock:
            return self._owner(value)

    def get_or_insert_durable(self, user_id, candidate):
        with self.lock:
            slot = self._slot(candidate)
            if slot is not None:
                for u, n in self.records:
                    if u == user_id and self._slot(n) == slot:
                        return n
            if self._owner(candidate.value) is not None:
                raise pygamlastan.NameIdValueTaken()
            self.records.append((user_id, candidate))
            return candidate

    def insert(self, user_id, name_id):
        with self.lock:
            if self._owner(name_id.value) is not None:
                raise pygamlastan.NameIdValueTaken()
            if self._durable_clash(user_id, name_id):
                raise pygamlastan.NameIdDurableExists()
            self.records.append((user_id, name_id))

    def replace(self, user_id, name_id):
        with self.lock:
            owner = self._owner(name_id.value)
            if owner is not None and owner != user_id:
                raise pygamlastan.NameIdValueTaken()
            if self._durable_clash(user_id, name_id):
                raise pygamlastan.NameIdDurableExists()
            self.records = [(u, n) for u, n in self.records if n.value != name_id.value]
            self.records.append((user_id, name_id))

    def remove(self, value):
        with self.lock:
            self.records = [(u, n) for u, n in self.records if n.value != value]

    def remove_all(self, user_id):
        with self.lock:
            self.records = [(u, n) for u, n in self.records if u != user_id]


class NoValueUniqueness(GoodStore):
    """Forgot the unique index on the NameID value."""

    def insert(self, user_id, name_id):
        with self.lock:
            self.records.append((user_id, name_id))


class CheckThenInsert(GoodStore):
    """Looks, releases the lock, then writes: what a backend without a unique
    index does. The pause makes the race certain."""

    def get_or_insert_durable(self, user_id, candidate):
        slot = self._slot(candidate)
        with self.lock:
            for u, n in self.records:
                if u == user_id and slot is not None and self._slot(n) == slot:
                    return n
        time.sleep(0.02)  # releases the GIL, so other threads run in the window
        with self.lock:
            self.records.append((user_id, candidate))
        return candidate


class Reassigns(GoodStore):
    """`replace` moves a record to whichever user asks."""

    def replace(self, user_id, name_id):
        with self.lock:
            self.records = [(u, n) for u, n in self.records if n.value != name_id.value]
            self.records.append((user_id, name_id))


def test_the_check_names_are_listed():
    assert "value_is_unique" in idp.STORE_CONFORMANCE_CHECKS
    assert "concurrent_get_or_insert_converges_on_one_identifier" in idp.STORE_CONFORMANCE_CHECKS
    assert len(idp.STORE_CONFORMANCE_CHECKS) == len(set(idp.STORE_CONFORMANCE_CHECKS)) > 5


def test_a_correct_store_passes_every_check():
    idp.check_store_conformance(GoodStore)


def test_a_store_without_value_uniqueness_is_caught():
    with pytest.raises(pygamlastan.StoreConformanceError) as caught:
        idp.check_store_conformance(NoValueUniqueness)
    assert caught.value.check == "value_is_unique"
    assert "already in use" in caught.value.message
    assert str(caught.value).startswith("value_is_unique: ")


def test_a_check_then_insert_store_loses_the_race():
    # This also proves the GIL is released while the suite runs: the racing
    # threads call back into this Python object, so holding it would deadlock.
    with pytest.raises(pygamlastan.StoreConformanceError) as caught:
        idp.check_store_conformance_one(
            "concurrent_get_or_insert_converges_on_one_identifier", CheckThenInsert, threads=8
        )
    assert caught.value.check == "concurrent_get_or_insert_converges_on_one_identifier"


def test_a_replace_that_moves_a_record_to_another_user_is_caught():
    with pytest.raises(pygamlastan.StoreConformanceError) as caught:
        idp.check_store_conformance_one("replace_upserts_by_value", Reassigns)
    assert "moved a record to another user" in caught.value.message
    # The same store is fine on the checks it does not break.
    idp.check_store_conformance_one("value_is_unique", Reassigns)


def test_a_factory_that_raises_is_a_setup_error_not_a_conformance_failure():
    def factory():
        raise RuntimeError("cannot reach the test database")

    with pytest.raises(RuntimeError, match="cannot reach the test database"):
        idp.check_store_conformance(factory)


def test_an_unknown_check_name_lists_the_known_ones():
    with pytest.raises(pygamlastan.StoreConformanceError, match="known checks"):
        idp.check_store_conformance_one("no_such_check", GoodStore)


def test_threads_must_be_positive():
    with pytest.raises(ValueError, match="threads"):
        idp.check_store_conformance(GoodStore, threads=0)


def test_a_store_that_passes_also_backs_the_identity_database():
    store = GoodStore()
    db = idp.IdentDb("https://idp.example.org/idp", store=store)
    sp = "https://sp.example.org/sp"
    first = db.persistent_nameid("alice", sp)
    assert db.persistent_nameid("alice", sp).value == first.value
    assert db.find_local_id(first) == "alice"
