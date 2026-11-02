"""The `KeyValueStore` (Eptid cache) and `AssertionStore` conformance suites.

Like the identity-store suite, these are run against a real instance of the
backend; here they run against in-process stores, a correct one that must pass
and deliberately broken ones that must fail the right check.
"""

import threading

import pytest

import pygamlastan
from pygamlastan import idp, xml


# --------------------------------------------------------------------------- #
# KeyValueStore
# --------------------------------------------------------------------------- #

class Cache:
    def __init__(self):
        self.data = {}
        self.lock = threading.Lock()

    def get(self, key):
        with self.lock:
            return self.data.get(key)

    def set(self, key, value):
        with self.lock:
            self.data[key] = value

    def remove(self, key):
        with self.lock:
            self.data.pop(key, None)


class PrefixCache(Cache):
    """Answers a lookup from any stored key that starts with the one asked for."""

    def get(self, key):
        with self.lock:
            return next((v for k, v in self.data.items() if k.startswith(key)), None)


class EvictingCache(Cache):
    """Keeps only the most recent hundred keys."""

    def set(self, key, value):
        with self.lock:
            self.data.pop(key, None)
            self.data[key] = value
            while len(self.data) > 100:
                self.data.pop(next(iter(self.data)))


class RemoveDoesNothing(Cache):
    def remove(self, key):
        pass


def test_the_kv_check_names_are_listed():
    assert "keys_are_exact" in idp.KV_CONFORMANCE_CHECKS
    assert "values_are_not_evicted" in idp.KV_CONFORMANCE_CHECKS


def test_a_correct_cache_passes_every_kv_check():
    idp.check_kv_conformance(Cache)


@pytest.mark.parametrize(
    "broken, check",
    [
        (PrefixCache, "keys_are_exact"),
        (EvictingCache, "values_are_not_evicted"),
        (RemoveDoesNothing, "remove_is_scoped"),
    ],
)
def test_a_broken_cache_is_caught_by_the_right_check(broken, check):
    with pytest.raises(pygamlastan.StoreConformanceError) as caught:
        idp.check_kv_conformance(broken)
    assert caught.value.check == check


def test_a_single_kv_check_can_be_run_by_name():
    idp.check_kv_conformance_one("keys_are_exact", Cache)
    with pytest.raises(pygamlastan.StoreConformanceError) as caught:
        idp.check_kv_conformance_one("keys_are_exact", PrefixCache)
    assert caught.value.check == "keys_are_exact"


def test_a_kv_factory_that_raises_is_a_setup_error():
    def broken():
        raise RuntimeError("no database")

    with pytest.raises(RuntimeError, match="no database"):
        idp.check_kv_conformance(broken)


def test_an_unknown_kv_check_name_is_a_conformance_error():
    with pytest.raises(pygamlastan.StoreConformanceError, match="no_such_check"):
        idp.check_kv_conformance_one("no_such_check", Cache)


# --------------------------------------------------------------------------- #
# AssertionStore
# --------------------------------------------------------------------------- #

class Delegating:
    """A Python object over the built-in store, so the suite runs through the
    Python adapter. Subclasses bend one method."""

    def __init__(self):
        self.inner = idp.InMemoryAssertionStore()
        self.lock = threading.Lock()

    def store_assertion(self, assertion):
        with self.lock:
            self.inner.store_assertion(assertion)

    def get_assertion(self, assertion_id):
        with self.lock:
            return self.inner.get_assertion(assertion_id)

    def assertions_for_subject(self, value):
        with self.lock:
            return list(self.inner.assertions_for_subject(value))

    def remove_assertion(self, assertion_id):
        with self.lock:
            self.inner.remove_assertion(assertion_id)


class ListsEveryonesAssertions(Delegating):
    """A subject lookup that forgot its WHERE."""

    def assertions_for_subject(self, value):
        with self.lock:
            return [
                a
                for who in ("alice", "Alice", "alice2", "bob", "ali")
                for a in self.inner.assertions_for_subject(who)
            ]


class RemoveDoesNothingAssertions(Delegating):
    def remove_assertion(self, assertion_id):
        pass


class XmlAssertionStore:
    """Persists assertions the way a SQL or Mongo backend has to: as XML, keeping
    nothing live. Reads rebuild native assertions with ``xml.parse_assertion``."""

    def __init__(self):
        self.xml_by_id = {}
        self.lock = threading.Lock()

    def store_assertion(self, assertion):
        with self.lock:
            # Replacing the document also moves an ID that is stored for a new subject.
            self.xml_by_id[assertion.id] = assertion.to_xml()

    def get_assertion(self, assertion_id):
        with self.lock:
            doc = self.xml_by_id.get(assertion_id)
        return None if doc is None else xml.parse_assertion(doc)

    def assertions_for_subject(self, value):
        with self.lock:
            docs = list(self.xml_by_id.values())
        parsed = (xml.parse_assertion(doc) for doc in docs)
        return [a for a in parsed if a.subject.name_id.value == value]

    def remove_assertion(self, assertion_id):
        with self.lock:
            self.xml_by_id.pop(assertion_id, None)


def test_an_assertion_store_that_persists_xml_passes_every_check():
    # Needs Assertion.to_xml: a backend that cannot serialize an assertion cannot
    # persist one, and the checks include the validity window and statements that
    # must survive the round trip.
    idp.check_assertion_store_conformance(XmlAssertionStore)


def test_the_engine_stores_assertions_as_xml_without_a_signature(rsa_keypair):
    from test_idp_orchestrator import _engine, _params, _subject

    store = XmlAssertionStore()
    engine, ref = _engine(rsa_keypair, assertions=store)
    issued = engine.create_authn_response(_params(), _subject(ref)).issued

    persisted = store.get_assertion(issued.assertion_id)
    assert persisted.id == issued.assertion_id
    assert persisted.subject.name_id.value
    # The model is persisted, not the signed document the SP received.
    assert "SignatureValue" in issued.xml
    assert "SignatureValue" not in store.xml_by_id[issued.assertion_id]


def test_the_assertion_check_names_are_listed():
    assert "subject_lookup_is_exact_and_isolated" in idp.ASSERTION_STORE_CONFORMANCE_CHECKS
    assert "concurrent_stores_lose_nothing" in idp.ASSERTION_STORE_CONFORMANCE_CHECKS


def test_the_built_in_assertion_store_passes_every_check():
    idp.check_assertion_store_conformance(idp.InMemoryAssertionStore)


def test_a_python_adapter_over_a_correct_store_passes_every_check():
    idp.check_assertion_store_conformance(Delegating)


@pytest.mark.parametrize(
    "broken, check",
    [
        (ListsEveryonesAssertions, "subject_lookup_is_exact_and_isolated"),
        (RemoveDoesNothingAssertions, "remove_is_scoped_and_clears_the_subject_index"),
    ],
)
def test_a_broken_assertion_store_is_caught_by_the_right_check(broken, check):
    with pytest.raises(pygamlastan.StoreConformanceError) as caught:
        idp.check_assertion_store_conformance(broken)
    assert caught.value.check == check


def test_an_assertion_factory_that_raises_is_a_setup_error():
    def broken():
        raise RuntimeError("no database")

    with pytest.raises(RuntimeError, match="no database"):
        idp.check_assertion_store_conformance(broken)


def test_a_single_assertion_check_can_be_run_by_name():
    idp.check_assertion_store_conformance_one("missing_assertion_is_absent", Delegating)
    with pytest.raises(pygamlastan.StoreConformanceError, match="no_such_check"):
        idp.check_assertion_store_conformance_one("no_such_check", Delegating)


def test_threads_must_be_positive_for_every_suite():
    for check, factory in (
        (idp.check_kv_conformance, Cache),
        (idp.check_assertion_store_conformance, Delegating),
    ):
        with pytest.raises(ValueError, match="threads"):
            check(factory, threads=0)


@pytest.mark.parametrize(
    "run",
    [
        idp.check_store_conformance,
        idp.check_kv_conformance,
        idp.check_assertion_store_conformance,
        lambda factory: idp.check_store_conformance_one(
            "concurrent_insert_of_one_value_has_one_winner", factory, threads=16
        ),
    ],
)
def test_a_failing_factory_is_called_once_and_nothing_else_runs(run):
    # A setup error stops at the first check, so a backend's constructor is not run
    # again for every check, and the concurrent checks never start their worker threads.
    calls = []

    def broken():
        calls.append(1)
        raise RuntimeError("no database")

    with pytest.raises(RuntimeError, match="no database"):
        run(broken)
    assert len(calls) == 1

