//! Bindings for `gamlastan::idp::orchestrator` - the IdP response engine.
//!
//! The application supplies identity facts (`AuthenticatedSubject`, an
//! `EstablishedSession` if one exists); the engine decides what the request
//! requires (`check_request`), derives the NameID, releases attributes and
//! signs the response (`create_authn_response`), or answers with a signed
//! protocol error (`create_denial_response`).
//!
//! Everything here is surfaced in the `pygamlastan.idp` module next to the
//! primitives it composes (`ReleasePolicy`, `IdentDb`, `AuthnBroker`, ...).

use chrono::{DateTime, Utc};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use gamlastan::idp as gi;
use gamlastan::idp::assertion_store::AssertionStore;
use gamlastan::idp::ident::StoreError;
use gamlastan::profiles::error::ProfileError;

use crate::core::{Assertion, Attribute, NameId};
use crate::crypto::SamlSigner;
use crate::errors::{profile_err, store_err};
use crate::idp::{
    method_to_py, AuthnBroker, AuthnMethod, IdentDb, InMemoryAssertionStore, ReleasePolicy,
};
use crate::metadata::EntityDescriptor;
use crate::profiles::ProcessedAuthnRequest;

/// A store failure is an operational fault (an outage), not something the SP
/// caused, so it is `SamlStoreError`; every other engine error is a
/// `SamlProfileError` (a configuration or programming fault).
fn engine_err(e: ProfileError) -> PyErr {
    match e {
        ProfileError::Store(s) => store_err(s),
        other => profile_err(other),
    }
}

// ---------------------------------------------------------------------------
// Denial
// ---------------------------------------------------------------------------

/// Why a request is refused with a signed SAML protocol error.
///
/// A closed set with a fixed `Status` mapping: nothing the SP sent reaches the
/// status message.
#[pyclass(
    module = "pygamlastan.idp",
    name = "Denial",
    frozen,
    eq,
    eq_int,
    hash,
    from_py_object,
    rename_all = "SCREAMING_SNAKE_CASE"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Denial {
    /// `IsPassive` and no usable session (`Responder/NoPassive`).
    NoPassive,
    /// No authentication method satisfies the requested context
    /// (`Responder/NoAuthnContext`).
    NoAuthnContext,
    /// The requested `NameIDPolicy` cannot be honoured
    /// (`Requester/InvalidNameIDPolicy`).
    InvalidNameIdPolicy,
    /// `AllowCreate="false"` and no identifier exists
    /// (`Requester/InvalidNameIDPolicy`).
    NameIdCreationNotAllowed,
    /// Attributes the SP requires were not released
    /// (`Requester/InvalidAttrNameOrValue`).
    MissingRequiredAttributes,
    /// The request names an `AttributeConsumingServiceIndex` the SP does not have.
    InvalidAttributeConsumingServiceIndex,
    /// Authentication failed (`Responder/AuthnFailed`).
    AuthnFailed,
    /// The user cancelled authentication (`Responder/AuthnFailed`).
    Cancelled,
}

impl From<gi::Denial> for Denial {
    fn from(d: gi::Denial) -> Self {
        match d {
            gi::Denial::NoPassive => Denial::NoPassive,
            gi::Denial::NoAuthnContext => Denial::NoAuthnContext,
            gi::Denial::InvalidNameIdPolicy => Denial::InvalidNameIdPolicy,
            gi::Denial::NameIdCreationNotAllowed => Denial::NameIdCreationNotAllowed,
            gi::Denial::MissingRequiredAttributes => Denial::MissingRequiredAttributes,
            gi::Denial::InvalidAttributeConsumingServiceIndex => {
                Denial::InvalidAttributeConsumingServiceIndex
            }
            gi::Denial::AuthnFailed => Denial::AuthnFailed,
            gi::Denial::Cancelled => Denial::Cancelled,
        }
    }
}

impl From<Denial> for gi::Denial {
    fn from(d: Denial) -> Self {
        match d {
            Denial::NoPassive => gi::Denial::NoPassive,
            Denial::NoAuthnContext => gi::Denial::NoAuthnContext,
            Denial::InvalidNameIdPolicy => gi::Denial::InvalidNameIdPolicy,
            Denial::NameIdCreationNotAllowed => gi::Denial::NameIdCreationNotAllowed,
            Denial::MissingRequiredAttributes => gi::Denial::MissingRequiredAttributes,
            Denial::InvalidAttributeConsumingServiceIndex => {
                gi::Denial::InvalidAttributeConsumingServiceIndex
            }
            Denial::AuthnFailed => gi::Denial::AuthnFailed,
            Denial::Cancelled => gi::Denial::Cancelled,
        }
    }
}

// ---------------------------------------------------------------------------
// AuthnMethodRef
// ---------------------------------------------------------------------------

/// Which authentication method ran: either a class ref given directly
/// (`AuthnMethodRef.inline`, for a proxy or a login flow outside the broker) or
/// a reference to a method registered in the `AuthnBroker`
/// (`AuthnMethodRef.broker`, the value `AuthnBroker.add` returned).
#[pyclass(
    module = "pygamlastan.idp",
    name = "AuthnMethodRef",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct AuthnMethodRef {
    inner: gi::AuthnMethodRef,
}

#[pymethods]
impl AuthnMethodRef {
    /// A class ref supplied directly, with no broker registration.
    ///
    /// **The engine verifies nothing about it.** For ``Comparison="exact"`` an
    /// inline class ref satisfies the request by *matching the request*, so an
    /// application that builds it from request data signs an assertion claiming
    /// an authentication context that was never established. Build it from what
    /// your login flow actually did (a constant, or the upstream IdP's reported
    /// context in a proxy), never from the ``AuthnRequest``. A registered
    /// ``AuthnMethodRef.broker`` is held to the broker's registration, but is
    /// still your claim about which method ran.
    #[staticmethod]
    #[pyo3(signature = (class_ref, authn_authority=None))]
    fn inline(class_ref: String, authn_authority: Option<String>) -> Self {
        AuthnMethodRef {
            inner: gi::AuthnMethodRef::Inline {
                class_ref,
                authn_authority,
            },
        }
    }

    /// A method registered in the broker, by the reference `AuthnBroker.add`
    /// returned. A reference the broker does not know is an error when the
    /// response is built, never a class ref taken from the string.
    #[staticmethod]
    fn broker(reference: String) -> Self {
        AuthnMethodRef {
            inner: gi::AuthnMethodRef::BrokerReference(reference),
        }
    }

    /// `"inline"` or `"broker"`.
    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner {
            gi::AuthnMethodRef::Inline { .. } => "inline",
            gi::AuthnMethodRef::BrokerReference(_) => "broker",
        }
    }
    #[getter]
    fn class_ref(&self) -> Option<String> {
        match &self.inner {
            gi::AuthnMethodRef::Inline { class_ref, .. } => Some(class_ref.clone()),
            gi::AuthnMethodRef::BrokerReference(_) => None,
        }
    }
    #[getter]
    fn authn_authority(&self) -> Option<String> {
        match &self.inner {
            gi::AuthnMethodRef::Inline {
                authn_authority, ..
            } => authn_authority.clone(),
            gi::AuthnMethodRef::BrokerReference(_) => None,
        }
    }
    #[getter]
    fn reference(&self) -> Option<String> {
        match &self.inner {
            gi::AuthnMethodRef::Inline { .. } => None,
            gi::AuthnMethodRef::BrokerReference(r) => Some(r.clone()),
        }
    }

    fn __repr__(&self) -> String {
        match &self.inner {
            gi::AuthnMethodRef::Inline {
                class_ref,
                authn_authority,
            } => {
                format!("AuthnMethodRef.inline({class_ref:?}, authn_authority={authn_authority:?})")
            }
            gi::AuthnMethodRef::BrokerReference(r) => format!("AuthnMethodRef.broker({r:?})"),
        }
    }
}

// ---------------------------------------------------------------------------
// AuthenticatedSubject / EstablishedSession
// ---------------------------------------------------------------------------

/// The authenticated subject, as the application knows it: its identifier, its
/// raw (pre-release, unfiltered) attributes, which method ran, when, and the
/// session index. The engine derives the NameID, the released attributes and
/// the authn context from these.
///
/// `authn_instant` must be timezone-aware. `None` means "now" (a fresh login);
/// when reusing a session, pass the session's own instant so
/// `AuthnStatement/@AuthnInstant` and `SessionNotOnOrAfter` reflect the real
/// moment.
#[pyclass(
    module = "pygamlastan.idp",
    name = "AuthenticatedSubject",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct AuthenticatedSubject {
    inner: gi::AuthenticatedSubject,
}

#[pymethods]
impl AuthenticatedSubject {
    #[new]
    #[pyo3(signature = (subject_id, attributes, authn_method, authn_instant=None, session_index=None))]
    fn new(
        subject_id: String,
        attributes: Vec<Attribute>,
        authn_method: AuthnMethodRef,
        authn_instant: Option<DateTime<Utc>>,
        session_index: Option<String>,
    ) -> Self {
        AuthenticatedSubject {
            inner: gi::AuthenticatedSubject {
                subject_id,
                attributes: attributes.into_iter().map(|a| a.inner).collect(),
                authn_method: authn_method.inner,
                authn_instant,
                session_index,
            },
        }
    }
    #[getter]
    fn subject_id(&self) -> String {
        self.inner.subject_id.clone()
    }
    #[getter]
    fn attributes(&self) -> Vec<Attribute> {
        self.inner
            .attributes
            .iter()
            .cloned()
            .map(Attribute::wrap)
            .collect()
    }
    #[getter]
    fn authn_method(&self) -> AuthnMethodRef {
        AuthnMethodRef {
            inner: self.inner.authn_method.clone(),
        }
    }
    #[getter]
    fn authn_instant(&self) -> Option<DateTime<Utc>> {
        self.inner.authn_instant
    }
    #[getter]
    fn session_index(&self) -> Option<String> {
        self.inner.session_index.clone()
    }
}

/// An SSO session the application already has for the browser: who it is for,
/// which method established it, when, and its session index. Pass it to
/// `ResponseEngine.check_request` so ForceAuthn, IsPassive and the requested
/// context can be weighed against it. `authn_instant` must be timezone-aware.
#[pyclass(
    module = "pygamlastan.idp",
    name = "EstablishedSession",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct EstablishedSession {
    inner: gi::EstablishedSession,
}

#[pymethods]
impl EstablishedSession {
    #[new]
    fn new(
        subject_id: String,
        authn_method: AuthnMethodRef,
        authn_instant: DateTime<Utc>,
        session_index: String,
    ) -> Self {
        EstablishedSession {
            inner: gi::EstablishedSession {
                subject_id,
                authn_method: authn_method.inner,
                authn_instant,
                session_index,
            },
        }
    }
    #[getter]
    fn subject_id(&self) -> String {
        self.inner.subject_id.clone()
    }
    #[getter]
    fn authn_method(&self) -> AuthnMethodRef {
        AuthnMethodRef {
            inner: self.inner.authn_method.clone(),
        }
    }
    #[getter]
    fn authn_instant(&self) -> DateTime<Utc> {
        self.inner.authn_instant
    }
    #[getter]
    fn session_index(&self) -> String {
        self.inner.session_index.clone()
    }
}

// ---------------------------------------------------------------------------
// ResponseParams
// ---------------------------------------------------------------------------

/// A processed AuthnRequest bound to the trusted metadata of the SP it came
/// from. The engine reads the SP's entity categories, `subject-id:req` and
/// `AttributeConsumingService` requirements from here.
///
/// The SAML 2.0 SP role is taken from `entity` itself, so the request, the role
/// and the entity cannot come from different SPs. Raises `SamlProfileError` if
/// `entity` is not the SP the request was validated for, or has no SAML 2.0 SP
/// role.
#[pyclass(module = "pygamlastan.idp", name = "ResponseParams", frozen)]
pub struct ResponseParams {
    inner: gi::ResponseParams,
}

#[pymethods]
impl ResponseParams {
    #[new]
    fn new(processed: &ProcessedAuthnRequest, entity: &EntityDescriptor) -> PyResult<Self> {
        gi::ResponseParams::from_entity(processed.inner.clone(), entity.inner.clone())
            .map(|inner| ResponseParams { inner })
            .map_err(engine_err)
    }
    /// The processed request these parameters were built from.
    #[getter]
    fn processed(&self) -> ProcessedAuthnRequest {
        ProcessedAuthnRequest::wrap(self.inner.processed.clone())
    }
}

// ---------------------------------------------------------------------------
// Disposition
// ---------------------------------------------------------------------------

/// What `check_request` decided. `kind` is one of:
///
/// * `"reuse_session"`: answer from `session` without authenticating again.
/// * `"authenticate"`: the user must log in; `methods` are the registered
///   methods that satisfy the request, strongest first (possibly empty, e.g.
///   when no broker methods are registered and the application authenticates
///   with an inline method).
/// * `"deny"`: refuse with a signed error; `denial` says why. Pass it to
///   `ResponseEngine.create_denial_response` without authenticating anyone.
#[pyclass(module = "pygamlastan.idp", name = "Disposition", frozen)]
pub struct Disposition {
    inner: gi::Disposition,
}

#[pymethods]
impl Disposition {
    #[getter]
    fn kind(&self) -> &'static str {
        match self.inner {
            gi::Disposition::ReuseSession { .. } => "reuse_session",
            gi::Disposition::Authenticate { .. } => "authenticate",
            gi::Disposition::Deny { .. } => "deny",
        }
    }
    /// The session to reuse (`"reuse_session"` only).
    #[getter]
    fn session(&self) -> Option<EstablishedSession> {
        match &self.inner {
            gi::Disposition::ReuseSession { session } => Some(EstablishedSession {
                inner: session.clone(),
            }),
            _ => None,
        }
    }
    /// Methods satisfying the request (`"authenticate"` only; else empty).
    #[getter]
    fn methods(&self) -> Vec<AuthnMethod> {
        match &self.inner {
            gi::Disposition::Authenticate { methods } => methods.iter().map(method_to_py).collect(),
            _ => Vec::new(),
        }
    }
    /// Why the request is refused (`"deny"` only).
    #[getter]
    fn denial(&self) -> Option<Denial> {
        match &self.inner {
            gi::Disposition::Deny { denial } => Some((*denial).into()),
            _ => None,
        }
    }
    fn __repr__(&self) -> String {
        match &self.inner {
            gi::Disposition::ReuseSession { .. } => "Disposition(reuse_session)".to_string(),
            gi::Disposition::Authenticate { methods } => {
                format!("Disposition(authenticate, {} method(s))", methods.len())
            }
            gi::Disposition::Deny { denial } => {
                format!("Disposition(deny, {:?})", Denial::from(*denial))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// A signed successful response with the identifiers an audit log needs
/// (response and assertion IDs, NameID, session index, expiry, and the names -
/// never the values - of the released attributes).
#[pyclass(module = "pygamlastan.idp", name = "IssuedResponse", frozen)]
pub struct IssuedResponse {
    inner: gi::IssuedResponse,
}

#[pymethods]
impl IssuedResponse {
    /// The signed response XML, ready to deliver over a binding.
    #[getter]
    fn xml(&self) -> String {
        self.inner.xml.clone()
    }
    #[getter]
    fn response_id(&self) -> String {
        self.inner.response_id.clone()
    }
    #[getter]
    fn assertion_id(&self) -> Option<String> {
        self.inner.assertion_id.clone()
    }
    #[getter]
    fn name_id(&self) -> NameId {
        NameId::wrap(self.inner.name_id.clone())
    }
    #[getter]
    fn session_index(&self) -> Option<String> {
        self.inner.session_index.clone()
    }
    /// The assertion's `NotOnOrAfter` (timezone-aware, UTC).
    #[getter]
    fn not_on_or_after(&self) -> DateTime<Utc> {
        self.inner.not_on_or_after
    }
    #[getter]
    fn released_attribute_names(&self) -> Vec<String> {
        self.inner.released_attribute_names.clone()
    }
}

/// A signed protocol error response. It has no assertion, subject or session:
/// only the XML and the response ID.
#[pyclass(module = "pygamlastan.idp", name = "DeniedResponse", frozen)]
pub struct DeniedResponse {
    inner: gi::DeniedResponse,
}

#[pymethods]
impl DeniedResponse {
    /// The signed response XML, ready to deliver over a binding.
    #[getter]
    fn xml(&self) -> String {
        self.inner.xml.clone()
    }
    #[getter]
    fn response_id(&self) -> String {
        self.inner.response_id.clone()
    }
}

/// The outcome of `create_authn_response`: either a signed successful response
/// (`issued`) or a signed protocol error (`denied`, with `denial` saying why).
/// A configuration or store fault is an exception, never an outcome.
#[pyclass(module = "pygamlastan.idp", name = "ResponseOutcome", frozen)]
pub struct ResponseOutcome {
    inner: gi::ResponseOutcome,
}

#[pymethods]
impl ResponseOutcome {
    #[getter]
    fn is_issued(&self) -> bool {
        matches!(self.inner, gi::ResponseOutcome::Issued(_))
    }
    /// The successful response, or `None` if the request was denied.
    #[getter]
    fn issued(&self) -> Option<IssuedResponse> {
        match &self.inner {
            gi::ResponseOutcome::Issued(i) => Some(IssuedResponse { inner: i.clone() }),
            gi::ResponseOutcome::Denied { .. } => None,
        }
    }
    /// The error response, or `None` if a response was issued.
    #[getter]
    fn denied(&self) -> Option<DeniedResponse> {
        match &self.inner {
            gi::ResponseOutcome::Issued(_) => None,
            gi::ResponseOutcome::Denied { response, .. } => Some(DeniedResponse {
                inner: response.clone(),
            }),
        }
    }
    /// Why the request was denied, or `None` if a response was issued.
    #[getter]
    fn denial(&self) -> Option<Denial> {
        match &self.inner {
            gi::ResponseOutcome::Issued(_) => None,
            gi::ResponseOutcome::Denied { denial, .. } => Some((*denial).into()),
        }
    }
    /// The signed response XML, whichever it is.
    #[getter]
    fn xml(&self) -> String {
        match &self.inner {
            gi::ResponseOutcome::Issued(i) => i.xml.clone(),
            gi::ResponseOutcome::Denied { response, .. } => response.xml.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// ResponseEngine
// ---------------------------------------------------------------------------

/// Adapter implementing `AssertionStore` by calling a Python object:
/// `store_assertion(assertion)`, `get_assertion(id) -> Assertion | None`,
/// `assertions_for_subject(name_id_value) -> Iterable[Assertion]` and
/// `remove_assertion(id)`, with assertions crossing as `core.Assertion`. Any
/// exception is a backend failure (`SamlStoreError`), never "no such assertion".
///
/// The engine itself only ever calls `store_assertion`; the other three serve the
/// back-channel query responders and the application's own logout code. Nothing in
/// pygamlastan calls them yet. gamlastan's query helpers
/// (`get_authn_statements`, `create_assertion_id_request_response`) refuse an
/// assertion for the wrong subject or ID, so whoever binds a responder on top of
/// this adapter gets that check by going through them; calling the adapter
/// directly does not. `check_assertion_store_conformance` tests a backend.
pub(crate) struct PyAssertionStore {
    obj: Py<PyAny>,
}

impl PyAssertionStore {
    pub(crate) fn new(obj: Py<PyAny>) -> Self {
        PyAssertionStore { obj }
    }
}

fn store_failure(e: PyErr) -> StoreError {
    StoreError::new(e)
}

impl AssertionStore for PyAssertionStore {
    fn store_assertion(
        &self,
        assertion: gamlastan::core::assertion::Assertion,
    ) -> Result<(), StoreError> {
        Python::attach(|py| {
            let a = Py::new(py, Assertion::wrap(assertion))?;
            self.obj
                .bind(py)
                .call_method1("store_assertion", (a,))
                .map(drop)
        })
        .map_err(store_failure)
    }
    fn get_assertion(
        &self,
        assertion_id: &str,
    ) -> Result<Option<gamlastan::core::assertion::Assertion>, StoreError> {
        Python::attach(|py| {
            let r = self
                .obj
                .bind(py)
                .call_method1("get_assertion", (assertion_id,))?;
            if r.is_none() {
                Ok(None)
            } else {
                Ok(Some(r.extract::<Assertion>()?.inner))
            }
        })
        .map_err(store_failure)
    }
    fn assertions_for_subject(
        &self,
        name_id_value: &str,
    ) -> Result<Vec<gamlastan::core::assertion::Assertion>, StoreError> {
        Python::attach(|py| {
            let r = self
                .obj
                .bind(py)
                .call_method1("assertions_for_subject", (name_id_value,))?;
            r.try_iter()?
                .map(|a| Ok(a?.extract::<Assertion>()?.inner))
                .collect::<PyResult<Vec<_>>>()
        })
        .map_err(store_failure)
    }
    fn remove_assertion(&self, assertion_id: &str) -> Result<(), StoreError> {
        Python::attach(|py| {
            self.obj
                .bind(py)
                .call_method1("remove_assertion", (assertion_id,))
                .map(drop)
        })
        .map_err(store_failure)
    }
}

/// The built-in store, or a caller-supplied Python object.
enum AssertionSource {
    Builtin(Py<InMemoryAssertionStore>),
    Custom(PyAssertionStore),
}

/// The IdP response engine: composes a `ReleasePolicy`, an `IdentDb`, an
/// `AuthnBroker`, an optional assertion store and a signer into the Web Browser
/// SSO response flow.
///
/// * `release`: `"policy"` (default) filters attributes through the
///   `ReleasePolicy` (entity categories, SP-requested attributes,
///   restrictions); `"pass_through"` releases exactly what the application
///   supplied, for a proxy whose attributes were already filtered upstream.
/// * `cert_der_b64`: the signing certificate, base64 DER (the body of the PEM,
///   no header lines), placed in `<ds:KeyInfo>`.
///
/// The engine holds references to the objects it is given, so later changes to
/// them (a policy entry added, a method registered) are seen by the next call.
/// Make those changes between calls: the policy, identity database, broker and
/// signer are borrowed for the whole of a call, including every callback into
/// your stores, so mutating one from inside a store callback raises
/// ``RuntimeError: Already borrowed`` (reported as a ``SamlStoreError``).
///
/// What the engine does not do, and the application must: enforce `Scoping`
/// (`ProxyCount`, `IDPList`) if it is a proxy, and compare a requested
/// `Subject` with the authenticated user (see
/// `AuthnRequest.requested_subject_name_id`), or refuse requests that name one.
#[pyclass(module = "pygamlastan.idp", name = "ResponseEngine")]
pub struct ResponseEngine {
    idp_entity_id: String,
    policy: Py<ReleasePolicy>,
    idents: Py<IdentDb>,
    broker: Py<AuthnBroker>,
    signer: Py<SamlSigner>,
    cert_der_b64: String,
    assertions: Option<AssertionSource>,
    pass_through: bool,
}

impl ResponseEngine {
    /// Borrow every part for the duration of one call and hand `f` the
    /// borrowed gamlastan engine.
    fn with_engine<R>(&self, py: Python<'_>, f: impl FnOnce(&gi::ResponseEngine) -> R) -> R {
        let policy = self.policy.bind(py).borrow();
        let idents = self.idents.bind(py).borrow();
        let broker = self.broker.bind(py).borrow();
        let signer = self.signer.bind(py).borrow();
        let builtin = match &self.assertions {
            Some(AssertionSource::Builtin(a)) => Some(a.bind(py).borrow()),
            _ => None,
        };
        let assertions: Option<&dyn AssertionStore> = match (&self.assertions, &builtin) {
            (Some(AssertionSource::Builtin(_)), Some(b)) => Some(&b.inner),
            (Some(AssertionSource::Custom(c)), _) => Some(c),
            _ => None,
        };
        let pass_through = gi::PassThroughRelease;
        let release: &dyn gi::AttributeRelease = if self.pass_through {
            &pass_through
        } else {
            &policy.inner
        };
        let engine = gi::ResponseEngine {
            idp_entity_id: &self.idp_entity_id,
            decisions: &policy.inner,
            release,
            idents: &idents.inner,
            broker: &broker.inner,
            assertions,
            signer: &signer.inner,
            cert_der_b64: &self.cert_der_b64,
        };
        f(&engine)
    }
}

#[pymethods]
impl ResponseEngine {
    #[new]
    #[pyo3(signature = (idp_entity_id, policy, idents, broker, signer, cert_der_b64, assertions=None, release="policy"))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        idp_entity_id: String,
        policy: Py<ReleasePolicy>,
        idents: Py<IdentDb>,
        broker: Py<AuthnBroker>,
        signer: Py<SamlSigner>,
        cert_der_b64: String,
        assertions: Option<Py<PyAny>>,
        release: &str,
    ) -> PyResult<Self> {
        let pass_through = match release {
            "policy" => false,
            "pass_through" => true,
            other => {
                return Err(PyValueError::new_err(format!(
                    "unknown release mode {other:?} (known: \"policy\", \"pass_through\")"
                )))
            }
        };
        Ok(ResponseEngine {
            idp_entity_id,
            policy,
            idents,
            broker,
            signer,
            cert_der_b64,
            assertions: assertions.map(|obj| {
                match obj.bind(py).extract::<Py<InMemoryAssertionStore>>() {
                    Ok(builtin) => AssertionSource::Builtin(builtin),
                    Err(_) => AssertionSource::Custom(PyAssertionStore { obj }),
                }
            }),
            pass_through,
        })
    }

    /// Decide what to do with a request, without any I/O: the ForceAuthn x
    /// IsPassive x RequestedAuthnContext matrix, weighed against `session` if
    /// the browser has one. Answers one of three things (see `Disposition`):
    /// reuse the session, authenticate, or deny. Call it before authenticating
    /// anyone, and act on `"deny"` without running a login.
    #[pyo3(signature = (params, session=None))]
    fn check_request(
        &self,
        py: Python<'_>,
        params: &ResponseParams,
        session: Option<&EstablishedSession>,
    ) -> Disposition {
        let inner = self.with_engine(py, |engine| {
            gi::check_request(engine, &params.inner, session.map(|s| &s.inner))
        });
        Disposition { inner }
    }

    /// Assemble and sign the response for an authenticated subject.
    ///
    /// Returns a `ResponseOutcome`: an issued response, or a signed denial when
    /// the request cannot be satisfied (an unsupported NameID format, a session
    /// that expired while you authenticated, a method that does not satisfy the
    /// requested context, attributes the SP requires that were not released).
    ///
    /// Raises `SamlStoreError` if the identity or assertion store failed (an
    /// outage is never read as "no record"), and `SamlProfileError` for a
    /// configuration fault (for example an `AuthnMethodRef.broker` the broker
    /// does not know, or a `ResponseParams` for a different SP).
    fn create_authn_response(
        &self,
        py: Python<'_>,
        params: &ResponseParams,
        subject: &AuthenticatedSubject,
    ) -> PyResult<ResponseOutcome> {
        self.with_engine(py, |engine| {
            gi::create_authn_response(engine, &params.inner, &subject.inner)
        })
        .map(|inner| ResponseOutcome { inner })
        .map_err(engine_err)
    }

    /// Assemble and sign a protocol error response. The Response envelope is
    /// always signed, whatever the per-SP signing targets.
    fn create_denial_response(
        &self,
        py: Python<'_>,
        params: &ResponseParams,
        denial: Denial,
    ) -> PyResult<DeniedResponse> {
        self.with_engine(py, |engine| {
            gi::create_denial_response(engine, &params.inner, &denial.into())
        })
        .map(|inner| DeniedResponse { inner })
        .map_err(engine_err)
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Denial>()?;
    m.add_class::<AuthnMethodRef>()?;
    m.add_class::<AuthenticatedSubject>()?;
    m.add_class::<EstablishedSession>()?;
    m.add_class::<ResponseParams>()?;
    m.add_class::<Disposition>()?;
    m.add_class::<IssuedResponse>()?;
    m.add_class::<DeniedResponse>()?;
    m.add_class::<ResponseOutcome>()?;
    m.add_class::<ResponseEngine>()?;
    Ok(())
}
