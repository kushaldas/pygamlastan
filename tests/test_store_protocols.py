"""The store protocols are declared in the stub, so they must exist at runtime too.

`from pygamlastan.idp import KeyValueStore` used to type-check and then raise
`ImportError`.
"""

import ast
import threading
from pathlib import Path

import pytest

import pygamlastan
from pygamlastan import idp
from test_kv_and_assertion_conformance import Cache, Delegating
from test_store_conformance import GoodStore

NAMES = ("IdentityStore", "KeyValueStore", "AssertionStore")


@pytest.mark.parametrize("name", NAMES)
def test_the_protocols_are_importable_from_idp(name):
    namespace = {}
    exec(f"from pygamlastan.idp import {name}", namespace)  # the statement that failed
    assert namespace[name] is getattr(idp, name)


def test_isinstance_checks_that_the_required_methods_exist():
    assert isinstance(Cache(), idp.KeyValueStore)
    assert isinstance(Delegating(), idp.AssertionStore)
    assert isinstance(idp.InMemoryAssertionStore(), idp.AssertionStore)
    assert isinstance(GoodStore(), idp.IdentityStore)
    # Not a store: nothing to call.
    for protocol in (idp.IdentityStore, idp.KeyValueStore, idp.AssertionStore):
        assert not isinstance(object(), protocol)
    # Missing a required method.
    class NoRemove:
        def get(self, key): ...
        def set(self, key, value): ...

    assert not isinstance(NoRemove(), idp.KeyValueStore)


def test_a_minimal_identity_store_matches_without_the_optional_methods():
    # GoodStore defines neither `find` nor `find_durable`; they are not members.
    store = GoodStore()
    assert not hasattr(store, "find") and not hasattr(store, "find_durable")
    assert isinstance(store, idp.IdentityStore)


def test_a_backend_can_inherit_the_protocol_explicitly():
    class Mine(idp.KeyValueStore):
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

    idp.check_kv_conformance(Mine)
    eptid = idp.Eptid("secret", store=Mine())
    assert eptid.get("https://idp.example.org/idp", "https://sp.example.org/sp", "alice")


def test_the_protocols_are_not_confused_with_each_other():
    cache = Cache()
    assert not isinstance(cache, idp.AssertionStore)
    assert not isinstance(cache, idp.IdentityStore)
    assert pygamlastan.idp.KeyValueStore is not pygamlastan.idp.AssertionStore


STUB = Path(__file__).resolve().parent.parent / "python" / "pygamlastan" / "idp.pyi"


@pytest.mark.skipif(not STUB.exists(), reason="stub not in this checkout")
@pytest.mark.parametrize("name", NAMES)
def test_the_stub_declares_the_same_runtime_checkable_protocol(name):
    # Type checkers read the stub, so a protocol that is runtime-checkable at runtime
    # must be declared so there too, or `isinstance(store, idp.<Name>)` is rejected.
    # The two definitions are written twice, so keep them from drifting apart.
    tree = ast.parse(STUB.read_text(encoding="utf-8"))
    (node,) = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == name]

    decorators = {ast.unparse(d) for d in node.decorator_list}
    assert "runtime_checkable" in decorators, f"{name} in idp.pyi is not @runtime_checkable"

    stub_methods = {
        item.name
        for item in node.body
        if isinstance(item, ast.FunctionDef) and not item.name.startswith("_")
    }
    runtime = getattr(idp, name)
    runtime_methods = {
        attr for attr, value in vars(runtime).items() if callable(value) and not attr.startswith("_")
    }
    assert stub_methods == runtime_methods, f"{name}: stub and runtime protocol disagree"
