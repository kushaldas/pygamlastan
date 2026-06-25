//! Bindings for `gamlastan::security` - the 32-check assertion/response
//! validator, its config, structured results, and the replay cache (built-in
//! plus a Python-implementable protocol).

use chrono::{DateTime, Utc};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use gamlastan::security as gs;

use crate::convert::new_submodule;
use crate::core::Response;

// ---------------------------------------------------------------------------
// SecurityConfig
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.security", name = "SecurityConfig", skip_from_py_object)]
#[derive(Clone)]
pub struct SecurityConfig {
    pub inner: gs::SecurityConfig,
}

#[pymethods]
impl SecurityConfig {
    #[new]
    fn new() -> Self {
        SecurityConfig { inner: gs::SecurityConfig::new() }
    }
    /// Permissive config for testing only (NOT for production). Emits a
    /// `UserWarning` because it disables security checks such as the
    /// signed-assertion requirement.
    #[staticmethod]
    fn permissive(py: Python<'_>) -> Self {
        crate::convert::warn(
            py,
            "SecurityConfig.permissive() disables SAML security checks (e.g. the \
             signed-assertion/response requirements) and must never be used in production.",
        );
        SecurityConfig { inner: gs::SecurityConfig::permissive() }
    }
    /// Strict config: all checks plus optional ones enabled.
    #[staticmethod]
    fn strict() -> Self {
        SecurityConfig { inner: gs::SecurityConfig::strict() }
    }

    #[getter]
    fn clock_skew_seconds(&self) -> u64 {
        self.inner.clock_skew_seconds
    }
    #[setter]
    fn set_clock_skew_seconds(&mut self, v: u64) {
        self.inner.clock_skew_seconds = v;
    }
    #[getter]
    fn require_signed_assertions(&self) -> bool {
        self.inner.require_signed_assertions
    }
    #[setter]
    fn set_require_signed_assertions(&mut self, v: bool) {
        self.inner.require_signed_assertions = v;
    }
    #[getter]
    fn require_signed_responses(&self) -> bool {
        self.inner.require_signed_responses
    }
    #[setter]
    fn set_require_signed_responses(&mut self, v: bool) {
        self.inner.require_signed_responses = v;
    }
    #[getter]
    fn max_assertion_age_seconds(&self) -> u64 {
        self.inner.max_assertion_age_seconds
    }
    #[setter]
    fn set_max_assertion_age_seconds(&mut self, v: u64) {
        self.inner.max_assertion_age_seconds = v;
    }
    #[getter]
    fn verify_destination(&self) -> bool {
        self.inner.verify_destination
    }
    #[setter]
    fn set_verify_destination(&mut self, v: bool) {
        self.inner.verify_destination = v;
    }
    #[getter]
    fn verify_recipient(&self) -> bool {
        self.inner.verify_recipient
    }
    #[setter]
    fn set_verify_recipient(&mut self, v: bool) {
        self.inner.verify_recipient = v;
    }

    /// Whether encrypted assertions are required (PEFIM and similar profiles).
    #[getter]
    fn require_encrypted_assertions(&self) -> bool {
        self.inner.require_encrypted_assertions
    }
    #[setter]
    fn set_require_encrypted_assertions(&mut self, v: bool) {
        self.inner.require_encrypted_assertions = v;
    }

    /// Reject signatures containing `<ds:Object>` elements (SAML errata E91).
    #[getter]
    fn reject_signatures_with_ds_object(&self) -> bool {
        self.inner.reject_signatures_with_ds_object
    }
    #[setter]
    fn set_reject_signatures_with_ds_object(&mut self, v: bool) {
        self.inner.reject_signatures_with_ds_object = v;
    }

    /// Enforce persistent-identifier uniqueness (E78). Requires a persistent-id
    /// store to be passed to `validate_response` to have any effect.
    #[getter]
    fn enforce_persistent_id_uniqueness(&self) -> bool {
        self.inner.enforce_persistent_id_uniqueness
    }
    #[setter]
    fn set_enforce_persistent_id_uniqueness(&mut self, v: bool) {
        self.inner.enforce_persistent_id_uniqueness = v;
    }

    /// Sanitize RelayState for XSS/CSRF (E90).
    #[getter]
    fn sanitize_relay_state(&self) -> bool {
        self.inner.sanitize_relay_state
    }
    #[setter]
    fn set_sanitize_relay_state(&mut self, v: bool) {
        self.inner.sanitize_relay_state = v;
    }

    /// Require integrity protection when CBC-mode encryption is used (E93).
    #[getter]
    fn require_integrity_with_cbc(&self) -> bool {
        self.inner.require_integrity_with_cbc
    }
    #[setter]
    fn set_require_integrity_with_cbc(&mut self, v: bool) {
        self.inner.require_integrity_with_cbc = v;
    }

    /// Check the client IP against the SubjectConfirmationData `Address`
    /// (optional; off by default). Requires `client_address` at validation time.
    #[getter]
    fn check_client_address(&self) -> bool {
        self.inner.check_client_address
    }
    #[setter]
    fn set_check_client_address(&mut self, v: bool) {
        self.inner.check_client_address = v;
    }
}

// ---------------------------------------------------------------------------
// ValidationResult / ValidationCheck
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.security", name = "ValidationCheck", frozen)]
pub struct ValidationCheck {
    #[pyo3(get)]
    check_number: u32,
    #[pyo3(get)]
    check_name: String,
    #[pyo3(get)]
    passed: bool,
    #[pyo3(get)]
    detail: Option<String>,
}

#[pymethods]
impl ValidationCheck {
    fn __repr__(&self) -> String {
        format!(
            "ValidationCheck(#{} {:?} passed={})",
            self.check_number, self.check_name, self.passed
        )
    }
}

fn check_to_py(c: &gs::ValidationCheck) -> ValidationCheck {
    ValidationCheck {
        check_number: c.check_number,
        check_name: c.check_name.to_string(),
        passed: c.passed,
        detail: c.detail.clone(),
    }
}

#[pyclass(module = "pygamlastan.security", name = "ValidationResult", frozen)]
pub struct ValidationResult {
    inner: gs::ValidationResult,
}

#[pymethods]
impl ValidationResult {
    fn is_valid(&self) -> bool {
        self.inner.is_valid()
    }
    fn __bool__(&self) -> bool {
        self.inner.is_valid()
    }
    fn total_checks(&self) -> usize {
        self.inner.total_checks()
    }
    #[getter]
    fn checks(&self) -> Vec<ValidationCheck> {
        self.inner.checks.iter().map(check_to_py).collect()
    }
    fn failures(&self) -> Vec<ValidationCheck> {
        self.inner.failures().into_iter().map(check_to_py).collect()
    }
    /// Only the checks that passed.
    fn passed_checks(&self) -> Vec<ValidationCheck> {
        self.inner.checks.iter().filter(|c| c.passed).map(check_to_py).collect()
    }
    /// The check with the given checklist number (1-32), or None. Lets a profile
    /// inspect one specific outcome without re-walking the full `checks` list.
    fn get(&self, check_number: u32) -> Option<ValidationCheck> {
        self.inner.checks.iter().find(|c| c.check_number == check_number).map(check_to_py)
    }
    /// The first check whose name equals `name` (case-insensitive), or None.
    fn by_name(&self, name: &str) -> Option<ValidationCheck> {
        self.inner
            .checks
            .iter()
            .find(|c| c.check_name.eq_ignore_ascii_case(name))
            .map(check_to_py)
    }
    fn __repr__(&self) -> String {
        format!(
            "ValidationResult(valid={}, checks={}, failures={})",
            self.inner.is_valid(),
            self.inner.total_checks(),
            self.inner.failures().len()
        )
    }
}

// ---------------------------------------------------------------------------
// Replay cache: built-in + Python protocol adapter
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.security", name = "InMemoryReplayCache")]
pub struct InMemoryReplayCache {
    inner: gs::InMemoryReplayCache,
}

#[pymethods]
impl InMemoryReplayCache {
    #[new]
    fn new() -> Self {
        InMemoryReplayCache { inner: gs::InMemoryReplayCache::new() }
    }
    /// True if `id` is new (inserted); False if already seen before `expiry`.
    fn check_and_insert(&self, id: &str, expiry: DateTime<Utc>) -> bool {
        use gs::ReplayCache;
        self.inner.check_and_insert(id, expiry)
    }
    fn cleanup(&self) {
        use gs::ReplayCache;
        self.inner.cleanup();
    }
    fn __len__(&self) -> usize {
        self.inner.len()
    }
}

/// Adapter implementing the Rust `ReplayCache` trait by calling into a Python
/// object that provides `check_and_insert(id, expiry)` and `cleanup()`.
pub struct PyReplayCache {
    pub obj: Py<PyAny>,
}

impl gs::ReplayCache for PyReplayCache {
    fn check_and_insert(&self, id: &str, expiry: DateTime<Utc>) -> bool {
        Python::attach(|py| {
            self.obj
                .bind(py)
                .call_method1("check_and_insert", (id, expiry))
                .and_then(|r| r.extract::<bool>())
                // Fail closed: on any Python-side error, treat as a replay.
                .unwrap_or(false)
        })
    }
    fn cleanup(&self) {
        Python::attach(|py| {
            let _ = self.obj.bind(py).call_method0("cleanup");
        });
    }
}

/// Adapter implementing the Rust `PersistentIdStore` trait (SAML errata E78:
/// persistent NameIDs must never be reassigned to a different principal) by
/// calling into a Python object that provides
/// `check_and_record(name_id, sp_entity_id, principal) -> bool`.
pub struct PyPersistentIdStore {
    pub obj: Py<PyAny>,
}

impl gs::name_id::PersistentIdStore for PyPersistentIdStore {
    fn check_and_record(&self, name_id: &str, sp_entity_id: &str, principal: &str) -> Result<(), String> {
        Python::attach(|py| {
            let ok = self
                .obj
                .bind(py)
                .call_method1("check_and_record", (name_id, sp_entity_id, principal))
                .and_then(|r| r.extract::<bool>())
                // Fail closed: on any Python-side error, treat as a conflict.
                .unwrap_or(false);
            if ok {
                Ok(())
            } else {
                Err(format!(
                    "persistent id {name_id:?} is already assigned to a different principal"
                ))
            }
        })
    }
}

// ---------------------------------------------------------------------------
// validate_response
// ---------------------------------------------------------------------------

/// Run the full Web-SSO validation suite over a parsed `Response`, returning a
/// structured `ValidationResult` (does not raise on validation failure).
///
/// `replay_cache` may be an `InMemoryReplayCache` or any object implementing
/// `check_and_insert(id, expiry)` / `cleanup()`.
///
/// `persistent_id_store` (optional) enables the E78 persistent-identifier
/// uniqueness check: any object with
/// `check_and_record(name_id, sp_entity_id, principal) -> bool` (returning False
/// when the id was already bound to a different principal). It only has effect
/// when `config.enforce_persistent_id_uniqueness` is True.
///
/// SECURITY: `now` exists only for test determinism and defaults to the real
/// system clock. Production callers must NOT pass `now` - supplying a fixed or
/// stale timestamp defeats the NotBefore/NotOnOrAfter/max-age validity checks.
/// Likewise, `response_signature_verified` / `verified_signed_ids` must come
/// from a real `crypto.SamlVerifier` result for THIS exact message, never be
/// hand-asserted (see `profiles.process_response_verified` for the safe path).
#[pyfunction]
#[pyo3(signature = (
    response, config, received_url, expected_idp_entity_id, sp_entity_id, acs_url,
    expected_request_id=None, client_address=None, relay_state=None,
    response_signature_verified=None, verified_signed_ids=None,
    current_proxy_depth=0, now=None, replay_cache=None, persistent_id_store=None,
))]
#[allow(clippy::too_many_arguments)]
fn validate_response(
    response: &Response,
    config: &SecurityConfig,
    received_url: &str,
    expected_idp_entity_id: &str,
    sp_entity_id: &str,
    acs_url: &str,
    expected_request_id: Option<String>,
    client_address: Option<String>,
    relay_state: Option<String>,
    response_signature_verified: Option<bool>,
    verified_signed_ids: Option<Vec<String>>,
    current_proxy_depth: u32,
    now: Option<DateTime<Utc>>,
    replay_cache: Option<Py<PyAny>>,
    persistent_id_store: Option<Py<PyAny>>,
) -> ValidationResult {
    // `gs::ValidationParams<'a>` borrows all its string inputs, so it cannot be
    // stored in a #[pyclass]. We instead take owned `String`/`Vec<String>` from
    // Python, keep them alive in these locals, and build the borrowed params
    // struct here - everything lives until the end of this call, which is all
    // the validator needs.
    let signed_ids = verified_signed_ids.unwrap_or_default();
    let signed_id_refs: Vec<&str> = signed_ids.iter().map(|s| s.as_str()).collect();
    // `now` is a parameter (not Utc::now() inside gamlastan) so validity-window
    // checks are testable; default to the real clock when the caller omits it.
    let now = now.unwrap_or_else(Utc::now);

    let params = gs::ValidationParams {
        received_url,
        expected_idp_entity_id,
        sp_entity_id,
        acs_url,
        expected_request_id: expected_request_id.as_deref(),
        client_address: client_address.as_deref(),
        relay_state: relay_state.as_deref(),
        response_signature_xml: None,
        response_signature_verified,
        verified_signed_ids: &signed_id_refs,
        current_proxy_depth,
        now,
    };

    // Wrap any Python replay cache / persistent-id store in their trait
    // adapters. `with_replay_cache` / `with_persistent_id_store` borrow
    // `&dyn ...` for the validator's lifetime, so the adapters must outlive the
    // `validate_response` call below (hence the separate lets). The chained
    // builder reassigns `validator` so both optional backends compose.
    let py_cache = replay_cache.map(|obj| PyReplayCache { obj });
    let py_pid = persistent_id_store.map(|obj| PyPersistentIdStore { obj });
    let mut validator = gs::AssertionValidator::new(&config.inner);
    if let Some(c) = &py_cache {
        validator = validator.with_replay_cache(c);
    }
    if let Some(s) = &py_pid {
        validator = validator.with_persistent_id_store(s);
    }
    let result = validator.validate_response(&response.inner, &params);
    ValidationResult { inner: result }
}

/// Run a single check standalone: the assertion-age check (checklist #0).
///
/// gamlastan's validator runs the full 32-check suite as a unit; this is the one
/// check it also exposes individually, useful for a profile that wants to gate
/// on assertion freshness on its own. For the other checks, run
/// `validate_response` and read the per-check outcomes from the result
/// (`ValidationResult.get(n)` / `.by_name(...)` / `.failures()`).
#[pyfunction]
fn check_assertion_age(
    config: &SecurityConfig,
    issue_instant: DateTime<Utc>,
    now: DateTime<Utc>,
) -> ValidationCheck {
    let validator = gs::AssertionValidator::new(&config.inner);
    check_to_py(&validator.check_assertion_age(issue_instant, now))
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "security")?;
    m.add_class::<SecurityConfig>()?;
    m.add_class::<ValidationResult>()?;
    m.add_class::<ValidationCheck>()?;
    m.add_class::<InMemoryReplayCache>()?;
    m.add_function(wrap_pyfunction!(validate_response, &m)?)?;
    m.add_function(wrap_pyfunction!(check_assertion_age, &m)?)?;
    Ok(())
}
