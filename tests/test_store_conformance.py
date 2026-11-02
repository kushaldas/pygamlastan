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
from pygamlastan import core, idp

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


# --------------------------------------------------------------------------- #
# Filtered lookup: IdentDb.find_nameid and the optional `find` pushdown
# --------------------------------------------------------------------------- #

IDP = "https://idp.example.org/idp"
SP_A = "https://a.example.org/sp"
SP_B = "https://b.example.org/sp"


def test_find_nameid_filters_on_every_field():
    db = idp.IdentDb(IDP)
    a = db.persistent_nameid("alice", SP_A)
    b = db.persistent_nameid("alice", SP_B)
    db.persistent_nameid("bob", SP_A)
    persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

    assert {n.value for n in db.find_nameid("alice")} == {a.value, b.value}  # no filter
    assert [n.value for n in db.find_nameid("alice", sp_name_qualifier=SP_A)] == [a.value]
    assert {n.value for n in db.find_nameid("alice", format=persistent)} == {a.value, b.value}
    assert db.find_nameid("alice", format="urn:example:other") == []
    assert db.find_nameid("nobody") == []
    # Users are isolated.
    assert all(n.value != a.value for n in db.find_nameid("bob"))
    # A set field must equal the record's exactly: a record without it is no match.
    assert db.find_nameid("alice", sp_provided_id="alias") == []
    updated = db.manage_name_id_new_id(a, "alias")
    assert [n.value for n in db.find_nameid("alice", sp_provided_id="alias")] == [updated.value]
    assert db.find_nameid("alice", name_qualifier=a.name_qualifier, sp_name_qualifier=SP_B)[0].value == b.value


class GoodStoreWithFind(GoodStore):
    """The same correct store, with the filter pushed down."""

    def __init__(self):
        super().__init__()
        self.find_calls = []

    def find(self, user_id, format, sp_name_qualifier, name_qualifier, sp_provided_id):
        self.find_calls.append((user_id, format, sp_name_qualifier, name_qualifier, sp_provided_id))
        want = {
            "format": format,
            "sp_name_qualifier": sp_name_qualifier,
            "name_qualifier": name_qualifier,
            "sp_provided_id": sp_provided_id,
        }
        with self.lock:
            return [
                n
                for u, n in self.records
                if u == user_id
                # A record with no Format counts as `unspecified`.
                and (format is None or (n.format or UNSPECIFIED) == format)
                and all(
                    w is None or getattr(n, k) == w
                    for k, w in want.items()
                    if k != "format"
                )
            ]


def test_a_pushed_down_find_is_used_and_passes_the_suite():
    store = GoodStoreWithFind()
    db = idp.IdentDb(IDP, store=store)
    mine = db.persistent_nameid("alice", SP_A)
    db.persistent_nameid("alice", SP_B)
    found = db.find_nameid("alice", sp_name_qualifier=SP_A)
    assert [n.value for n in found] == [mine.value]
    assert store.find_calls == [("alice", None, SP_A, None, None)]
    # The suite checks the backend's own `find` against the filter semantics.
    idp.check_store_conformance(GoodStoreWithFind)


@pytest.mark.parametrize("store_class", [GoodStore, GoodStoreWithFind])
def test_a_record_with_no_format_counts_as_unspecified_in_find_nameid(store_class):
    # The filter has the same meaning whether the backend filters for_user itself
    # (GoodStore defines no `find`) or pushes it down: an absent Format is
    # `unspecified`, so it is found by that format and by no other.
    db = idp.IdentDb(IDP, store=store_class())
    db.store("alice", core.NameId("no-format", sp_name_qualifier=SP_A, name_qualifier=IDP))
    persistent = db.persistent_nameid("alice", SP_A)

    def values(**filter_):
        return sorted(n.value for n in db.find_nameid("alice", **filter_))

    assert values(format=UNSPECIFIED) == ["no-format"]
    assert values(format=core.NAMEID_PERSISTENT) == [persistent.value]
    assert values() == sorted(["no-format", persistent.value])
    # It combines with the other fields like any other.
    assert values(format=UNSPECIFIED, sp_name_qualifier=SP_A) == ["no-format"]
    assert values(format=UNSPECIFIED, sp_name_qualifier=SP_B) == []


class FindIgnoresFilter(GoodStoreWithFind):
    def find(self, user_id, format, sp_name_qualifier, name_qualifier, sp_provided_id):
        return self.for_user(user_id)  # the filter is dropped


class FindReturnsAnotherUser(GoodStoreWithFind):
    def find(self, user_id, format, sp_name_qualifier, name_qualifier, sp_provided_id):
        return [n for u, n in self.records if u != user_id]  # forgot the user


def test_a_find_that_ignores_the_filter_is_refused_and_caught_by_the_suite():
    store = FindIgnoresFilter()
    db = idp.IdentDb(IDP, store=store)
    db.persistent_nameid("alice", SP_A)
    db.persistent_nameid("alice", SP_B)
    with pytest.raises(pygamlastan.SamlStoreError, match="does not satisfy the"):
        db.find_nameid("alice", sp_name_qualifier=SP_A)
    with pytest.raises(pygamlastan.StoreConformanceError) as caught:
        idp.check_store_conformance_one("find_filters_on_every_field", FindIgnoresFilter)
    assert caught.value.check == "find_filters_on_every_field"


def test_a_find_that_returns_another_users_records_is_refused():
    store = FindReturnsAnotherUser()
    db = idp.IdentDb(IDP, store=store)
    db.persistent_nameid("victim", SP_A)
    with pytest.raises(pygamlastan.SamlStoreError, match="does not attribute"):
        db.find_nameid("mallory", sp_name_qualifier=SP_A)


# --------------------------------------------------------------------------- #
# Eptid with a persistent cache
# --------------------------------------------------------------------------- #

EPTID_IDP = "https://idp.example.org/idp"
EPTID_SP = "https://sp.example.org/sp"


class DictCache:
    def __init__(self):
        self.data = {}
        self.calls = []

    def get(self, key):
        self.calls.append(("get", key))
        return self.data.get(key)

    def set(self, key, value):
        self.calls.append(("set", key))
        self.data[key] = value

    def remove(self, key):
        self.data.pop(key, None)


def test_eptid_remembers_issued_values_in_a_supplied_store():
    cache = DictCache()
    first = idp.Eptid("secret-1", store=cache).get(EPTID_IDP, EPTID_SP, "alice")
    assert list(cache.data) == [f"eptid:{EPTID_IDP}__{EPTID_SP}__alice"]
    assert cache.data[f"eptid:{EPTID_IDP}__{EPTID_SP}__alice"] == first
    assert first.startswith(f"{EPTID_IDP}!{EPTID_SP}!")

    # A fresh Eptid with a CHANGED secret still returns what was issued, because
    # it reads the cache: that is what the cache is for.
    changed = idp.Eptid("secret-2", store=cache)
    assert changed.get(EPTID_IDP, EPTID_SP, "alice") == first
    # Without the cache the new secret would issue a different value.
    assert idp.Eptid("secret-2").get(EPTID_IDP, EPTID_SP, "alice") != first
    # The name_id and attribute forms use the same cache.
    assert changed.name_id(EPTID_IDP, EPTID_SP, "alice").value == first


def test_a_failing_eptid_cache_is_an_error_not_a_recompute():
    class Down:
        def get(self, key):
            raise RuntimeError("cache down")

        set = remove = get

    eptid = idp.Eptid("secret", store=Down())
    with pytest.raises(pygamlastan.SamlStoreError, match="cache down"):
        eptid.get(EPTID_IDP, EPTID_SP, "alice")
