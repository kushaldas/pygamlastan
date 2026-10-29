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

    @staticmethod
    def _slot(n):
        fmt = n.format or UNSPECIFIED
        return None if fmt == TRANSIENT else (n.sp_name_qualifier, n.name_qualifier, fmt)

    def for_user(self, user_id):
        return [n for u, n in self.records if u == user_id]

    def user_for(self, value):
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


def test_an_honest_backend_is_unaffected():
    store, db, victim = _db_with_victim()
    assert db.persistent_nameid("victim", SP).value == victim.value  # find path
    mine = db.persistent_nameid("alice", SP)  # insert path
    assert mine.value != victim.value
    assert db.find_local_id(mine) == "alice"
    # A transient NameID has no slot to verify and is never stored.
    assert db.transient_nameid("alice", SP).format == TRANSIENT
