//! Bindings for gamlastan's backend conformance suites: `IdentityStore`,
//! `KeyValueStore` (the `Eptid` cache) and `AssertionStore`.
//!
//! The record-shaped store has no default write methods because a non-atomic
//! default would silently leave a race open, and nothing in a Python adapter
//! can detect a missing unique index by itself: it only misbehaves under load.
//! The suite checks that a backend honours the contract the response engine
//! relies on (value uniqueness, the durable `(user, SP, NameQualifier, format)`
//! constraint on every write path, scoped removal, and two concurrent checks).

use pyo3::prelude::*;
use pyo3::types::PyModule;
use std::sync::Mutex;

use gamlastan::idp::assertion_store::conformance as aconf;
use gamlastan::idp::ident::conformance as gconf;
use gamlastan::idp::ident::kv_conformance as kconf;

use crate::errors::StoreConformanceError;
use crate::idp::{PyIdentityStore, PyKeyValueStore};
use crate::orchestrator::PyAssertionStore;

fn conformance_err(py: Python<'_>, e: gconf::ConformanceError) -> PyErr {
    let err = StoreConformanceError::new_err(e.to_string());
    // Best effort: the failing check's name and message as attributes.
    let value = err.value(py);
    let _ = value.setattr("check", e.check);
    let _ = value.setattr("message", e.message);
    err
}

/// Run `run` against stores produced by calling `new_store`, with the GIL
/// released: the concurrent checks call into the backend from several threads,
/// and each of those takes the GIL itself, so holding it here would deadlock.
///
/// A factory that raises is a setup error, not a conformance failure: the first
/// such exception is re-raised as it was.
fn run_suite<S>(
    py: Python<'_>,
    new_store: Py<PyAny>,
    adapt: fn(Py<PyAny>) -> S,
    run: impl FnOnce(&dyn Fn() -> S) -> Result<(), gconf::ConformanceError> + Send,
) -> PyResult<()> {
    let factory_failure: Mutex<Option<PyErr>> = Mutex::new(None);
    let result = py.detach(|| {
        let make = || {
            Python::attach(|py| match new_store.bind(py).call0() {
                Ok(obj) => adapt(obj.unbind()),
                Err(e) => {
                    factory_failure.lock().unwrap().get_or_insert(e);
                    // Nothing to test; the failure above is raised afterwards.
                    adapt(py.None())
                }
            })
        };
        run(&make)
    });
    if let Some(e) = factory_failure.into_inner().unwrap() {
        return Err(e);
    }
    result.map_err(|e| conformance_err(py, e))
}

fn options(threads: usize) -> PyResult<gconf::Options> {
    if threads == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "threads must be at least 1 (the concurrent checks always use at least 2)",
        ));
    }
    Ok(gconf::Options { threads })
}

/// Check that an `IdentityStore` backend honours the contract the response
/// engine relies on. Raises `StoreConformanceError` (with `.check` and
/// `.message`) on the first violation.
///
/// `new_store` is called with no arguments and must return a **fresh, empty**
/// store each time: a new collection or table, or one that has been cleared.
/// Each check gets its own. Run it against a real instance of the backend with
/// its real indexes; a store that serialises every call can pass the concurrent
/// checks without having the constraint, and a race between separate processes
/// is not detected.
#[pyfunction]
#[pyo3(signature = (new_store, threads=16))]
fn check_store_conformance(py: Python<'_>, new_store: Py<PyAny>, threads: usize) -> PyResult<()> {
    let opts = options(threads)?;
    run_suite(py, new_store, PyIdentityStore::new, |make| {
        gconf::check_with(make, &opts)
    })
}

/// Run the single check called `name` (one of `STORE_CONFORMANCE_CHECKS`).
/// Raises `StoreConformanceError` for a violation or an unknown name.
#[pyfunction]
#[pyo3(signature = (name, new_store, threads=16))]
fn check_store_conformance_one(
    py: Python<'_>,
    name: String,
    new_store: Py<PyAny>,
    threads: usize,
) -> PyResult<()> {
    let opts = options(threads)?;
    run_suite(py, new_store, PyIdentityStore::new, |make| {
        gconf::check_one(&name, make, &opts)
    })
}

/// Check that a key-value cache backend (the `store` of an `Eptid`) honours its
/// contract: absent keys, exact keys, scoped removal, no eviction, and concurrent
/// writers. Raises `StoreConformanceError` (with `.check` and `.message`) on the
/// first violation. `new_store` returns a **fresh, empty** store each call.
#[pyfunction]
#[pyo3(signature = (new_store, threads=16))]
fn check_kv_conformance(py: Python<'_>, new_store: Py<PyAny>, threads: usize) -> PyResult<()> {
    let opts = options(threads)?;
    run_suite(py, new_store, PyKeyValueStore::new, |make| {
        kconf::check_with(make, &opts)
    })
}

/// Run the single check called `name` (one of `KV_CONFORMANCE_CHECKS`).
#[pyfunction]
#[pyo3(signature = (name, new_store, threads=16))]
fn check_kv_conformance_one(
    py: Python<'_>,
    name: String,
    new_store: Py<PyAny>,
    threads: usize,
) -> PyResult<()> {
    let opts = options(threads)?;
    run_suite(py, new_store, PyKeyValueStore::new, |make| {
        kconf::check_one(&name, make, &opts)
    })
}

/// Check that an `AssertionStore` backend honours its contract: exact subject
/// lookup, no duplicates, a re-stored ID moving between subjects, removal
/// clearing the subject index, the validity window surviving, and concurrent
/// stores. Raises `StoreConformanceError` (with `.check` and `.message`) on the
/// first violation. `new_store` returns a **fresh, empty** store each call.
#[pyfunction]
#[pyo3(signature = (new_store, threads=16))]
fn check_assertion_store_conformance(
    py: Python<'_>,
    new_store: Py<PyAny>,
    threads: usize,
) -> PyResult<()> {
    let opts = options(threads)?;
    run_suite(py, new_store, PyAssertionStore::new, |make| {
        aconf::check_with(make, &opts)
    })
}

/// Run the single check called `name` (one of `ASSERTION_STORE_CONFORMANCE_CHECKS`).
#[pyfunction]
#[pyo3(signature = (name, new_store, threads=16))]
fn check_assertion_store_conformance_one(
    py: Python<'_>,
    name: String,
    new_store: Py<PyAny>,
    threads: usize,
) -> PyResult<()> {
    let opts = options(threads)?;
    run_suite(py, new_store, PyAssertionStore::new, |make| {
        aconf::check_one(&name, make, &opts)
    })
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("STORE_CONFORMANCE_CHECKS", gconf::CHECKS.to_vec())?;
    m.add_function(wrap_pyfunction!(check_store_conformance, m)?)?;
    m.add_function(wrap_pyfunction!(check_store_conformance_one, m)?)?;
    m.add("KV_CONFORMANCE_CHECKS", kconf::CHECKS.to_vec())?;
    m.add_function(wrap_pyfunction!(check_kv_conformance, m)?)?;
    m.add_function(wrap_pyfunction!(check_kv_conformance_one, m)?)?;
    m.add("ASSERTION_STORE_CONFORMANCE_CHECKS", aconf::CHECKS.to_vec())?;
    m.add_function(wrap_pyfunction!(check_assertion_store_conformance, m)?)?;
    m.add_function(wrap_pyfunction!(check_assertion_store_conformance_one, m)?)?;
    Ok(())
}
