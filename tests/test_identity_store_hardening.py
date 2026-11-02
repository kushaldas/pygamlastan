"""Defences around a Python `IdentityStore` backend.

The backend is the part of the system least under the library's control, and a
NameID handed to the wrong user is account takeover at every SP that has seen
it. These tests cover what the binding adds on top of gamlastan's own checks.
"""

import pytest

import pygamlastan
from pygamlastan import core, idp

IDP = "https://idp.example.org/idp"
SP = "https://sp.example.org/sp"
OTHER_SP = "https://other.example.org/sp"

TRANSIENT = core.NAMEID_TRANSIENT
UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"


class Store:
    """A correct record-shaped store with switches that make it misbehave."""

    def __init__(self):
        self.records = []  # (user_id, NameId)
        self.wrong_user_for = None  # find_durable ignores the user and returns this user's record
        self.wrong_slot = False  # find_durable returns the user's record for another SP
        self.hijack_insert = None  # get_or_insert_durable returns this user's record
        self.wrong_owner = None  # user_for names this user whoever holds the value

    @staticmethod
    def _slot(n):
        fmt = n.format or UNSPECIFIED
        return None if fmt == TRANSIENT else (n.sp_name_qualifier, n.name_qualifier, fmt)

    def for_user(self, user_id):
        return [n for u, n in self.records if u == user_id]

    def user_for(self, value):
        if self.wrong_owner is not None:
            return self.wrong_owner
        return next((u for u, n in self.records if n.value == value), None)

    def find_durable(self, user_id, sp_name_qualifier, name_qualifier, format):
        if self.wrong_user_for is not None:
            return next(n for u, n in self.records if u == self.wrong_user_for)
        if self.wrong_slot:
            return next((n for u, n in self.records if u == user_id), None)
        want = (sp_name_qualifier, name_qualifier, format)
        return next((n for u, n in self.records if u == user_id and self._slot(n) == want), None)

    def get_or_insert_durable(self, user_id, candidate):
        if self.hijack_insert is not None:
            return next(n for u, n in self.records if u == self.hijack_insert)
        slot = self._slot(candidate)
        for u, n in self.records:
            if u == user_id and slot is not None and self._slot(n) == slot:
                return n
        self.insert(user_id, candidate)
        return candidate

    def insert(self, user_id, name_id):
        if self.user_for(name_id.value) is not None:
            raise pygamlastan.NameIdValueTaken()
        self.records.append((user_id, name_id))

    def replace(self, user_id, name_id):
        owner = self.user_for(name_id.value)
        if owner is not None and owner != user_id:
            raise pygamlastan.NameIdValueTaken()
        self.records = [(u, n) for u, n in self.records if n.value != name_id.value]
        self.records.append((user_id, name_id))

    def remove(self, value):
        self.records = [(u, n) for u, n in self.records if n.value != value]

    def remove_all(self, user_id):
        self.records = [(u, n) for u, n in self.records if u != user_id]


def _db_with_victim():
    store = Store()
    db = idp.IdentDb(IDP, store=store)
    victim = db.persistent_nameid("victim", SP)
    return store, db, victim


# --------------------------------------------------------------------------- #
# The exception hierarchy
# --------------------------------------------------------------------------- #

def test_a_store_outage_is_not_an_ident_error():
    assert issubclass(pygamlastan.SamlStoreError, pygamlastan.SamlError)
    assert not issubclass(pygamlastan.SamlStoreError, pygamlastan.SamlIdentError)
    # Conflicts are ident outcomes, as before.
    assert issubclass(pygamlastan.NameIdValueTaken, pygamlastan.SamlIdentError)
    assert issubclass(pygamlastan.NameIdDurableExists, pygamlastan.SamlIdentError)


def test_an_existing_ident_handler_cannot_swallow_an_outage():
    class Down:
        def __getattr__(self, name):
            def fail(*a, **k):
                raise RuntimeError("db down")
            return fail

    db = idp.IdentDb(IDP, store=Down())
    nid = core.NameId("x", format=core.NAMEID_PERSISTENT)
    swallowed = False
    with pytest.raises(pygamlastan.SamlStoreError, match="db down"):
        try:
            db.find_local_id(nid)
        except pygamlastan.SamlIdentError:  # code written before store errors existed
            swallowed = True
    assert not swallowed


# --------------------------------------------------------------------------- #
# Records a backend returns must be the caller's own
# --------------------------------------------------------------------------- #

def test_a_find_durable_that_returns_another_users_record_is_refused():
    store, db, victim = _db_with_victim()
    store.wrong_user_for = "victim"  # the query "forgot" the user
    with pytest.raises(pygamlastan.SamlStoreError, match="does not attribute"):
        db.persistent_nameid("mallory", SP)
    # Nothing was adopted or written for the attacker.
    assert db.name_ids_for("mallory") == []


def test_a_find_durable_that_returns_the_wrong_slot_is_refused():
    store, db, _ = _db_with_victim()
    db.persistent_nameid("alice", OTHER_SP)
    store.wrong_slot = True  # a wrong index: alice's record for another SP
    with pytest.raises(pygamlastan.SamlStoreError, match="not the durable NameID requested"):
        db.persistent_nameid("alice", SP)


def test_a_get_or_insert_durable_that_returns_another_users_record_is_refused():
    store, db, _ = _db_with_victim()
    store.hijack_insert = "victim"
    # find_durable finds nothing for mallory, so the insert path is taken.
    with pytest.raises(pygamlastan.SamlStoreError, match="does not attribute"):
        db.persistent_nameid("mallory", SP)


def test_a_reverse_index_that_names_the_wrong_owner_is_refused():
    store, db, victim = _db_with_victim()
    store.wrong_owner = "mallory"  # a stale or wrong user_for index
    with pytest.raises(pygamlastan.SamlStoreError, match="do not include it"):
        db.find_local_id(victim)
    # NameIDMapping / ManageNameID act on this answer, so they refuse it too.
    with pytest.raises(pygamlastan.SamlStoreError):
        db.manage_name_id_terminate(victim)


def test_verification_can_be_turned_off_for_a_trusted_store():
    store = Store()
    db = idp.IdentDb(IDP, store=store, verify_store=False)
    victim = db.persistent_nameid("victim", SP)
    store.wrong_user_for = "victim"
    # With the check off the wrong record is believed: that is what it protects.
    assert db.persistent_nameid("mallory", SP).value == victim.value


def test_an_honest_backend_is_unaffected():
    store, db, victim = _db_with_victim()
    assert db.persistent_nameid("victim", SP).value == victim.value  # find path
    mine = db.persistent_nameid("alice", SP)  # insert path
    assert mine.value != victim.value
    assert db.find_local_id(mine) == "alice"
    # A transient NameID has no slot to verify and is never stored.
    assert db.transient_nameid("alice", SP).format == TRANSIENT


# --------------------------------------------------------------------------- #
# The for_user fallback: a minimal backend defines neither `find` nor
# `find_durable`, so the binding filters `for_user` itself. The ownership check
# must not depend on whether those optional methods exist.
# --------------------------------------------------------------------------- #

class LeakyForUser:
    """No `find` / `find_durable` (both optional), and a `for_user` that
    forgot its `WHERE user_id = ...`: it returns everyone's records."""

    def __init__(self):
        self.rec = []

    def for_user(self, user_id):
        return [n for _u, n in self.rec]  # BUG: ignores user_id

    def user_for(self, value):
        return next((u for u, n in self.rec if n.value == value), None)

    def insert(self, user_id, name_id):
        self.rec.append((user_id, name_id))

    def replace(self, user_id, name_id):
        pass

    def get_or_insert_durable(self, user_id, candidate):
        self.insert(user_id, candidate)
        return candidate

    def remove(self, value):
        pass

    def remove_all(self, user_id):
        pass


def _leaky_db_with_victim():
    store = LeakyForUser()
    db = idp.IdentDb(IDP, store=store)
    # Written through the (correct) insert path, as a real victim's would be.
    victim = core.NameId("victim-value", format=core.NAMEID_PERSISTENT, sp_name_qualifier=SP, name_qualifier=IDP)
    store.insert("victim", victim)
    return store, db, victim


def test_a_for_user_that_forgot_the_user_cannot_hand_over_a_persistent_nameid():
    _, db, victim = _leaky_db_with_victim()
    with pytest.raises(pygamlastan.SamlStoreError, match="does not attribute"):
        db.persistent_nameid("mallory", SP)


def test_a_for_user_that_forgot_the_user_cannot_leak_through_find_nameid():
    _, db, _ = _leaky_db_with_victim()
    with pytest.raises(pygamlastan.SamlStoreError, match="does not attribute"):
        db.find_nameid("mallory")


def test_a_for_user_that_forgot_the_user_cannot_leak_through_name_ids_for():
    _, db, _ = _leaky_db_with_victim()
    with pytest.raises(pygamlastan.SamlStoreError, match="does not attribute"):
        db.name_ids_for("mallory")
    # The owner still gets their own record.
    assert [n.value for n in db.name_ids_for("victim")] == ["victim-value"]


def test_the_conformance_suite_also_catches_a_for_user_that_forgot_the_user():
    with pytest.raises(pygamlastan.StoreConformanceError) as caught:
        idp.check_store_conformance(LeakyForUser)
    assert caught.value.check  # some check named the violation


# --------------------------------------------------------------------------- #
# The EPTID cache is trusted, but its values must have the right shape
# --------------------------------------------------------------------------- #

class Cache:
    def __init__(self):
        self.data = {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value):
        self.data[key] = value

    def remove(self, key):
        self.data.pop(key, None)


def test_an_eptid_cache_value_of_the_wrong_shape_is_refused():
    cache = Cache()
    eptid = idp.Eptid("secret", store=cache)
    good = eptid.get(IDP, SP, "alice")
    key = f"eptid:{IDP}__{SP}__alice"
    assert eptid.get(IDP, SP, "alice") == good  # an honest cache is unaffected

    # `!` is legal in an entity ID, so a longer SP ID must not pass for this one.
    for poisoned in (
        "ATTACKERCONTROLLEDVALUE",
        f"{IDP}!{OTHER_SP}!abc",
        f"{IDP}!{SP}!",
        f"{IDP}!{SP}!other!abc",
    ):
        cache.data[key] = poisoned
        with pytest.raises(pygamlastan.SamlStoreError, match="shape of an identifier"):
            eptid.get(IDP, SP, "alice")
        with pytest.raises(pygamlastan.SamlStoreError, match="shape of an identifier"):
            eptid.name_id(IDP, SP, "alice")
        with pytest.raises(pygamlastan.SamlStoreError, match="shape of an identifier"):
            eptid.attribute(IDP, SP, "alice")


def test_eptid_verification_can_be_turned_off_for_values_from_an_older_entity_id():
    cache = Cache()
    old = "https://old-idp.example/idp!" + SP + "!abc"
    cache.data[f"eptid:{IDP}__{SP}__alice"] = old
    with pytest.raises(pygamlastan.SamlStoreError, match="shape of an identifier"):
        idp.Eptid("secret", store=cache).get(IDP, SP, "alice")
    assert idp.Eptid("secret", store=cache, verify_store=False).get(IDP, SP, "alice") == old


def test_the_md5_eptid_digest_warns_that_it_is_in_use():
    with pytest.warns(UserWarning, match="MD5"):
        idp.Eptid("secret", digest="pysaml2-md5", allow_legacy_md5=True)


# --------------------------------------------------------------------------- #
# Policy lifetimes cannot panic the constructor
# --------------------------------------------------------------------------- #

def test_out_of_range_lifetimes_are_policy_errors_not_panics():
    for kwarg in ("session_lifetime_seconds", "lifetime_seconds"):
        for huge in (2**62, 10**18, 2**63 - 1):
            with pytest.raises(pygamlastan.SamlPolicyError, match="out of range"):
                idp.PolicyEntry(**{kwarg: huge})
    # The largest representable value is still accepted.
    idp.PolicyEntry(session_lifetime_seconds=9_223_372_036_854_775)
