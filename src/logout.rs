//! Bindings for `gamlastan::profiles::logout` - SAML 2.0 Single Logout (SLO).
//!
//! Surfaces the SP-initiated logout surface eduID's `global_logout` /
//! `handle_logout_response` loop needs: an `SpLogoutRequestOptions` +
//! `create_sp_logout_request` builder, the transport-agnostic
//! `SpLogoutOrchestrator` state machine (the equivalent of pysaml2's
//! `global_logout`/`do_logout`/`handle_logout_response`), the IdP/SP
//! `LogoutResponse` builders (success / partial / error), and
//! `validate_logout_request`.
//!
//! `create_idp_propagation_request` (IdP fan-out to session participants) is
//! deliberately not bound yet: it depends on the `profiles::session`
//! `SessionParticipant`/session-store surface, which is a separate module not
//! required by the SP-side flow. The orchestrator covers SP-driven logout; the
//! IdP side builds responses with the helpers here.

use chrono::{DateTime, Utc};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use gamlastan::core::protocol::{Status, StatusCode};
use gamlastan::profiles::logout as gl;

use crate::convert::new_submodule;
use crate::core::{LogoutRequest, LogoutResponse, NameId};
use crate::errors::profile_err;

// ---------------------------------------------------------------------------
// SpLogoutRequestOptions / create_sp_logout_request
// ---------------------------------------------------------------------------

/// Options for building an SP-initiated `<samlp:LogoutRequest>`.
#[pyclass(module = "pygamlastan.logout", name = "SpLogoutRequestOptions")]
pub struct SpLogoutRequestOptions {
    inner: gl::SpLogoutRequestOptions,
}

#[pymethods]
impl SpLogoutRequestOptions {
    #[new]
    #[pyo3(signature = (
        sp_entity_id,
        name_id,
        session_indexes=None,
        reason=None,
        destination=None,
        not_on_or_after=None,
    ))]
    fn new(
        sp_entity_id: String,
        name_id: NameId,
        session_indexes: Option<Vec<String>>,
        reason: Option<String>,
        destination: Option<String>,
        not_on_or_after: Option<DateTime<Utc>>,
    ) -> Self {
        SpLogoutRequestOptions {
            inner: gl::SpLogoutRequestOptions {
                sp_entity_id,
                name_id: name_id.inner,
                session_indexes: session_indexes.unwrap_or_default(),
                reason,
                destination,
                not_on_or_after,
            },
        }
    }
}

/// Build an SP-initiated LogoutRequest from the given options.
#[pyfunction]
fn create_sp_logout_request(options: &SpLogoutRequestOptions) -> PyResult<LogoutRequest> {
    let req = gl::create_sp_logout_request(&options.inner).map_err(profile_err)?;
    Ok(LogoutRequest::wrap(req))
}

// ---------------------------------------------------------------------------
// LogoutResponse builders (success / partial / error)
// ---------------------------------------------------------------------------

/// Build a success `<samlp:LogoutResponse>`.
#[pyfunction]
#[pyo3(signature = (entity_id, in_response_to, destination=None))]
fn create_logout_response_success(
    entity_id: &str,
    in_response_to: &str,
    destination: Option<&str>,
) -> LogoutResponse {
    LogoutResponse::wrap(gl::create_logout_response_success(
        entity_id,
        in_response_to,
        destination,
    ))
}

/// Build a partial-logout `<samlp:LogoutResponse>` (top-level Success with a
/// `PartialLogout` sub-status: some session participants could not be logged
/// out).
#[pyfunction]
#[pyo3(signature = (entity_id, in_response_to, destination=None))]
fn create_logout_response_partial(
    entity_id: &str,
    in_response_to: &str,
    destination: Option<&str>,
) -> LogoutResponse {
    LogoutResponse::wrap(gl::create_logout_response_partial(
        entity_id,
        in_response_to,
        destination,
    ))
}

/// Build an error `<samlp:LogoutResponse>` carrying the given top-level status
/// code (e.g. `core.STATUS_RESPONDER`) and an optional human-readable message.
#[pyfunction]
#[pyo3(signature = (entity_id, in_response_to, status_code, status_message=None, destination=None))]
fn create_logout_response_error(
    entity_id: &str,
    in_response_to: &str,
    status_code: String,
    status_message: Option<String>,
    destination: Option<&str>,
) -> LogoutResponse {
    let status = Status {
        status_code: StatusCode {
            value: status_code,
            sub_status: None,
        },
        status_message,
        status_detail: None,
    };
    LogoutResponse::wrap(gl::create_logout_response(
        entity_id,
        in_response_to,
        destination,
        status,
    ))
}

// ---------------------------------------------------------------------------
// validate_logout_request
// ---------------------------------------------------------------------------

/// Validate an incoming LogoutRequest: NameID present and (if present)
/// NotOnOrAfter not expired, allowing `clock_skew_seconds` of skew. Raises
/// `SamlProfileError` if invalid.
#[pyfunction]
#[pyo3(signature = (request, now, clock_skew_seconds=180))]
fn validate_logout_request(
    request: &LogoutRequest,
    now: DateTime<Utc>,
    clock_skew_seconds: u64,
) -> PyResult<()> {
    gl::validate_logout_request(&request.inner, now, clock_skew_seconds).map_err(profile_err)
}

// ---------------------------------------------------------------------------
// SpLogoutOrchestrator + helper types
// ---------------------------------------------------------------------------

/// A session authority/participant the SP must log out from.
#[pyclass(module = "pygamlastan.logout", name = "LogoutTarget", frozen, from_py_object)]
#[derive(Clone)]
pub struct LogoutTarget {
    inner: gl::LogoutTarget,
}

#[pymethods]
impl LogoutTarget {
    #[new]
    #[pyo3(signature = (entity_id, name_id, slo_url, slo_binding, session_indexes=None))]
    fn new(
        entity_id: String,
        name_id: NameId,
        slo_url: String,
        slo_binding: String,
        session_indexes: Option<Vec<String>>,
    ) -> Self {
        LogoutTarget {
            inner: gl::LogoutTarget {
                entity_id,
                name_id: name_id.inner,
                session_indexes: session_indexes.unwrap_or_default(),
                slo_url,
                slo_binding,
            },
        }
    }
    #[getter]
    fn entity_id(&self) -> &str {
        &self.inner.entity_id
    }
    #[getter]
    fn slo_url(&self) -> &str {
        &self.inner.slo_url
    }
    #[getter]
    fn slo_binding(&self) -> &str {
        &self.inner.slo_binding
    }
    #[getter]
    fn session_indexes(&self) -> Vec<String> {
        self.inner.session_indexes.clone()
    }
}

/// A LogoutRequest ready to be delivered by the caller's transport.
#[pyclass(module = "pygamlastan.logout", name = "PendingLogoutRequest", frozen)]
pub struct PendingLogoutRequest {
    inner: gl::PendingLogoutRequest,
}

#[pymethods]
impl PendingLogoutRequest {
    #[getter]
    fn entity_id(&self) -> &str {
        &self.inner.entity_id
    }
    /// The LogoutRequest to deliver (sign before front-channel delivery).
    #[getter]
    fn request(&self) -> LogoutRequest {
        LogoutRequest::wrap(self.inner.request.clone())
    }
    #[getter]
    fn binding(&self) -> &str {
        &self.inner.binding
    }
    #[getter]
    fn destination(&self) -> &str {
        &self.inner.destination
    }
}

/// Outcome of correlating one LogoutResponse with its outstanding request.
#[pyclass(module = "pygamlastan.logout", name = "LogoutResponseOutcome", frozen)]
pub struct LogoutResponseOutcome {
    inner: gl::LogoutResponseOutcome,
}

#[pymethods]
impl LogoutResponseOutcome {
    #[getter]
    fn entity_id(&self) -> &str {
        &self.inner.entity_id
    }
    #[getter]
    fn success(&self) -> bool {
        self.inner.success
    }
    #[getter]
    fn partial(&self) -> bool {
        self.inner.partial
    }
    fn __repr__(&self) -> String {
        format!(
            "LogoutResponseOutcome(entity_id={:?}, success={}, partial={})",
            self.inner.entity_id, self.inner.success, self.inner.partial
        )
    }
}

/// State of one target in an SP-driven multi-entity logout. `kind` is one of
/// `"pending"`, `"in_progress"`, `"succeeded"`, `"failed"`.
#[pyclass(module = "pygamlastan.logout", name = "TargetLogoutState", frozen)]
pub struct TargetLogoutState {
    inner: gl::TargetLogoutState,
}

#[pymethods]
impl TargetLogoutState {
    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner {
            gl::TargetLogoutState::Pending => "pending",
            gl::TargetLogoutState::InProgress { .. } => "in_progress",
            gl::TargetLogoutState::Succeeded => "succeeded",
            gl::TargetLogoutState::Failed { .. } => "failed",
        }
    }
    /// The outstanding LogoutRequest ID (only for `in_progress`).
    #[getter]
    fn request_id(&self) -> Option<&str> {
        match &self.inner {
            gl::TargetLogoutState::InProgress { request_id } => Some(request_id),
            _ => None,
        }
    }
    /// The failure reason (only for `failed`).
    #[getter]
    fn reason(&self) -> Option<&str> {
        match &self.inner {
            gl::TargetLogoutState::Failed { reason } => Some(reason),
            _ => None,
        }
    }
    fn __repr__(&self) -> String {
        format!("TargetLogoutState(kind={:?})", self.kind())
    }
}

/// Aggregate progress across all logout targets.
#[pyclass(module = "pygamlastan.logout", name = "LogoutPropagationResult", frozen)]
pub struct LogoutPropagationResult {
    inner: gl::LogoutPropagationResult,
}

#[pymethods]
impl LogoutPropagationResult {
    #[getter]
    fn total_participants(&self) -> usize {
        self.inner.total_participants
    }
    #[getter]
    fn successful_logouts(&self) -> usize {
        self.inner.successful_logouts
    }
    #[getter]
    fn failed_participants(&self) -> Vec<String> {
        self.inner.failed_participants.clone()
    }
    /// Whether all participants were successfully logged out.
    fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }
    /// Whether at least one but not all participants were logged out.
    fn is_partial(&self) -> bool {
        self.inner.is_partial()
    }
}

/// Transport-agnostic state machine for SP-initiated logout across every entity
/// that holds a session for the principal. Drive it: `add_target()` for each
/// entity, then loop `next_request()` -> deliver -> `handle_response()` (or
/// `mark_failed()` on transport error) until `is_complete()`.
#[pyclass(module = "pygamlastan.logout", name = "SpLogoutOrchestrator")]
pub struct SpLogoutOrchestrator {
    inner: gl::SpLogoutOrchestrator,
}

#[pymethods]
impl SpLogoutOrchestrator {
    #[new]
    #[pyo3(signature = (sp_entity_id, reason=None))]
    fn new(sp_entity_id: String, reason: Option<String>) -> Self {
        let mut inner = gl::SpLogoutOrchestrator::new(sp_entity_id);
        if let Some(reason) = reason {
            inner = inner.with_reason(reason);
        }
        SpLogoutOrchestrator { inner }
    }
    /// Register an entity that must be logged out.
    fn add_target(&mut self, target: LogoutTarget) {
        self.inner.add_target(target.inner);
    }
    /// Produce the next LogoutRequest to deliver, or None if none are pending.
    fn next_request(&mut self) -> PyResult<Option<PendingLogoutRequest>> {
        let pending = self.inner.next_request().map_err(profile_err)?;
        Ok(pending.map(|inner| PendingLogoutRequest { inner }))
    }
    /// Correlate a LogoutResponse with its outstanding request and record the
    /// outcome. Raises `SamlProfileError` if it matches no outstanding request
    /// or the issuer does not match the target.
    fn handle_response(&mut self, response: &LogoutResponse) -> PyResult<LogoutResponseOutcome> {
        let inner = self
            .inner
            .handle_response(&response.inner)
            .map_err(profile_err)?;
        Ok(LogoutResponseOutcome { inner })
    }
    /// Record a transport-level failure for an entity.
    fn mark_failed(&mut self, entity_id: &str, failure_reason: String) {
        self.inner.mark_failed(entity_id, failure_reason);
    }
    /// The current state of a target entity, if known.
    fn target_state(&self, entity_id: &str) -> Option<TargetLogoutState> {
        self.inner
            .target_state(entity_id)
            .map(|s| TargetLogoutState { inner: s.clone() })
    }
    /// Whether every target reached a final state (succeeded or failed).
    fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }
    /// Aggregate progress across all targets.
    fn progress(&self) -> LogoutPropagationResult {
        LogoutPropagationResult {
            inner: self.inner.progress(),
        }
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "logout")?;

    m.add_class::<SpLogoutRequestOptions>()?;
    m.add_class::<LogoutTarget>()?;
    m.add_class::<PendingLogoutRequest>()?;
    m.add_class::<LogoutResponseOutcome>()?;
    m.add_class::<TargetLogoutState>()?;
    m.add_class::<LogoutPropagationResult>()?;
    m.add_class::<SpLogoutOrchestrator>()?;

    m.add_function(wrap_pyfunction!(create_sp_logout_request, &m)?)?;
    m.add_function(wrap_pyfunction!(create_logout_response_success, &m)?)?;
    m.add_function(wrap_pyfunction!(create_logout_response_partial, &m)?)?;
    m.add_function(wrap_pyfunction!(create_logout_response_error, &m)?)?;
    m.add_function(wrap_pyfunction!(validate_logout_request, &m)?)?;

    // Logout reason URIs.
    m.add("REASON_USER", gl::reason::USER)?;
    m.add("REASON_ADMIN", gl::reason::ADMIN)?;

    Ok(())
}
