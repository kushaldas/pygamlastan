//! Bindings for `gamlastan::core` - owned SAML 2.0 types, constants, namespaces.
//!
//! Each Python class wraps the corresponding *owned* gamlastan type (never a
//! borrowed `*Ref`). Getters clone nested owned values into their own wrappers.

use pyo3::prelude::*;
use pyo3::types::{PyList, PyModule};

use gamlastan::core::assertion as ga;
use gamlastan::core::protocol as gp;
use gamlastan::core::{constants as gc, namespace as gn};

use crate::convert::new_submodule;
use crate::errors::core_err;

// ---------------------------------------------------------------------------
// Helpers to move owned values in/out of the #[pyclass] wrappers.
// ---------------------------------------------------------------------------

/// Declare a `#[pyclass]` newtype wrapping an owned gamlastan type.
///
/// Every core type is exposed this way, which encodes three deliberate choices:
///   * `frozen` - the wrappers are immutable from Python; getters return clones,
///     so there is no interior mutability to guard and they are `Send`/`Sync`.
///   * `from_py_object` - opts in (pyo3 0.29 made this explicit for `Clone`
///     types) so a wrapper can be *passed back* into a function by value, e.g.
///     `NameId`/`Attribute` flowing into the profiles builders.
///   * `pub inner` - sibling binding modules (crypto, profiles, idp, ...) read
///     the underlying gamlastan value directly instead of going through Python.
///
/// `wrap()` is the single owned-value → Python-object constructor used at every
/// FFI boundary (right after a `*Ref::to_owned()`).
macro_rules! wrapper {
    ($py_name:literal, $name:ident, $inner:ty) => {
        #[pyclass(module = "pygamlastan.core", name = $py_name, frozen, from_py_object)]
        #[derive(Clone)]
        pub struct $name {
            pub inner: $inner,
        }
        impl $name {
            pub fn wrap(inner: $inner) -> Self {
                Self { inner }
            }
        }
    };
}

wrapper!("Issuer", Issuer, ga::Issuer);
wrapper!("NameId", NameId, ga::NameId);
wrapper!("NameIdPolicy", NameIdPolicy, ga::NameIdPolicy);
wrapper!(
    "SubjectConfirmationData",
    SubjectConfirmationData,
    ga::SubjectConfirmationData
);
wrapper!(
    "SubjectConfirmation",
    SubjectConfirmation,
    ga::SubjectConfirmation
);
wrapper!("Subject", Subject, ga::Subject);
wrapper!(
    "AudienceRestriction",
    AudienceRestriction,
    ga::AudienceRestriction
);
wrapper!("ProxyRestriction", ProxyRestriction, ga::ProxyRestriction);
wrapper!("Conditions", Conditions, ga::Conditions);
wrapper!("SubjectLocality", SubjectLocality, ga::SubjectLocality);
wrapper!("AuthnContext", AuthnContext, ga::AuthnContext);
wrapper!("AuthnStatement", AuthnStatement, ga::AuthnStatement);
wrapper!("Attribute", Attribute, ga::Attribute);
wrapper!(
    "AttributeStatement",
    AttributeStatement,
    ga::AttributeStatement
);
wrapper!("Assertion", Assertion, ga::types::Assertion);
wrapper!("StatusCode", StatusCode, gp::StatusCode);
wrapper!("Status", Status, gp::Status);
wrapper!(
    "RequestedAuthnContext",
    RequestedAuthnContext,
    gp::RequestedAuthnContext
);
wrapper!("Scoping", Scoping, gp::Scoping);
wrapper!("AuthnRequest", AuthnRequest, gp::AuthnRequest);
wrapper!("Response", Response, gp::Response);
wrapper!("LogoutRequest", LogoutRequest, gp::LogoutRequest);
wrapper!("LogoutResponse", LogoutResponse, gp::LogoutResponse);

/// Convert a typed gamlastan `AttributeValue` into the natural Python object:
/// str / int / bool / bytes / `NameId` / None. XML-valued attributes are handed
/// back as their (lossy) text so callers get a `str` rather than raw bytes.
fn attr_value_to_py(py: Python<'_>, v: &ga::AttributeValue) -> PyResult<Py<PyAny>> {
    use ga::AttributeValue as V;
    Ok(match v {
        V::String(s) => s.into_pyobject(py)?.into_any().unbind(),
        V::Integer(i) => i.into_pyobject(py)?.into_any().unbind(),
        // `bool::into_pyobject` yields a `Borrowed` reference to Python's shared
        // True/False singleton; `.to_owned()` turns it into an owned `Bound`
        // before `.into_any()` can consume it (the other arms already own).
        V::Boolean(b) => b.into_pyobject(py)?.to_owned().into_any().unbind(),
        V::DateTime(s) => s.into_pyobject(py)?.into_any().unbind(),
        V::Base64(b) => pyo3::types::PyBytes::new(py, b).into_any().unbind(),
        V::NameId(n) => NameId::wrap(n.clone())
            .into_pyobject(py)?
            .into_any()
            .unbind(),
        V::Xml(b) => String::from_utf8_lossy(b)
            .into_pyobject(py)?
            .into_any()
            .unbind(),
        V::Null => py.None(),
    })
}

/// A SAML name can be a plaintext `NameID` or an `EncryptedID`. We surface only
/// the plaintext case to Python (returning `None` for an encrypted id, which the
/// caller is expected to decrypt first via the crypto module). This keeps the
/// common getters simple instead of forcing every caller to handle a union.
fn nameid_opt(v: &Option<ga::NameIdOrEncryptedId>) -> Option<NameId> {
    match v {
        Some(ga::NameIdOrEncryptedId::NameId(n)) => Some(NameId::wrap(n.clone())),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Issuer
// ---------------------------------------------------------------------------

#[pymethods]
impl Issuer {
    #[new]
    #[pyo3(signature = (value, format=None, name_qualifier=None, sp_name_qualifier=None))]
    fn new(
        value: String,
        format: Option<String>,
        name_qualifier: Option<String>,
        sp_name_qualifier: Option<String>,
    ) -> Self {
        Issuer::wrap(ga::Issuer {
            value,
            format,
            name_qualifier,
            sp_name_qualifier,
        })
    }
    #[getter]
    fn value(&self) -> &str {
        &self.inner.value
    }
    #[getter]
    fn format(&self) -> Option<&str> {
        self.inner.format.as_deref()
    }
    #[getter]
    fn name_qualifier(&self) -> Option<&str> {
        self.inner.name_qualifier.as_deref()
    }
    #[getter]
    fn sp_name_qualifier(&self) -> Option<&str> {
        self.inner.sp_name_qualifier.as_deref()
    }
    fn __repr__(&self) -> String {
        format!("Issuer(value={:?})", self.inner.value)
    }
}

// ---------------------------------------------------------------------------
// NameId / NameIdPolicy
// ---------------------------------------------------------------------------

#[pymethods]
impl NameId {
    #[new]
    #[pyo3(signature = (value, format=None, name_qualifier=None, sp_name_qualifier=None, sp_provided_id=None))]
    fn new(
        value: String,
        format: Option<String>,
        name_qualifier: Option<String>,
        sp_name_qualifier: Option<String>,
        sp_provided_id: Option<String>,
    ) -> Self {
        NameId::wrap(ga::NameId {
            value,
            format,
            name_qualifier,
            sp_name_qualifier,
            sp_provided_id,
        })
    }
    #[getter]
    fn value(&self) -> &str {
        &self.inner.value
    }
    #[getter]
    fn format(&self) -> Option<&str> {
        self.inner.format.as_deref()
    }
    #[getter]
    fn name_qualifier(&self) -> Option<&str> {
        self.inner.name_qualifier.as_deref()
    }
    #[getter]
    fn sp_name_qualifier(&self) -> Option<&str> {
        self.inner.sp_name_qualifier.as_deref()
    }
    #[getter]
    fn sp_provided_id(&self) -> Option<&str> {
        self.inner.sp_provided_id.as_deref()
    }
    fn __repr__(&self) -> String {
        format!(
            "NameId(value={:?}, format={:?})",
            self.inner.value, self.inner.format
        )
    }
}

#[pymethods]
impl NameIdPolicy {
    #[new]
    #[pyo3(signature = (format=None, sp_name_qualifier=None, allow_create=true))]
    fn new(format: Option<String>, sp_name_qualifier: Option<String>, allow_create: bool) -> Self {
        NameIdPolicy::wrap(ga::NameIdPolicy {
            format,
            sp_name_qualifier,
            allow_create,
        })
    }
    #[getter]
    fn format(&self) -> Option<&str> {
        self.inner.format.as_deref()
    }
    #[getter]
    fn sp_name_qualifier(&self) -> Option<&str> {
        self.inner.sp_name_qualifier.as_deref()
    }
    #[getter]
    fn allow_create(&self) -> bool {
        self.inner.allow_create
    }
}

// ---------------------------------------------------------------------------
// Subject / SubjectConfirmation
// ---------------------------------------------------------------------------

#[pymethods]
impl SubjectConfirmationData {
    #[getter]
    fn not_before(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.inner.not_before
    }
    #[getter]
    fn not_on_or_after(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.inner.not_on_or_after
    }
    #[getter]
    fn recipient(&self) -> Option<&str> {
        self.inner.recipient.as_deref()
    }
    #[getter]
    fn in_response_to(&self) -> Option<&str> {
        self.inner.in_response_to.as_deref()
    }
    #[getter]
    fn address(&self) -> Option<&str> {
        self.inner.address.as_deref()
    }
}

#[pymethods]
impl SubjectConfirmation {
    #[getter]
    fn method(&self) -> &str {
        &self.inner.method
    }
    #[getter]
    fn name_id(&self) -> Option<NameId> {
        nameid_opt(&self.inner.name_id)
    }
    #[getter]
    fn subject_confirmation_data(&self) -> Option<SubjectConfirmationData> {
        self.inner
            .subject_confirmation_data
            .clone()
            .map(SubjectConfirmationData::wrap)
    }
}

#[pymethods]
impl Subject {
    #[getter]
    fn name_id(&self) -> Option<NameId> {
        nameid_opt(&self.inner.name_id)
    }
    #[getter]
    fn subject_confirmations(&self) -> Vec<SubjectConfirmation> {
        self.inner
            .subject_confirmations
            .iter()
            .cloned()
            .map(SubjectConfirmation::wrap)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Conditions
// ---------------------------------------------------------------------------

#[pymethods]
impl AudienceRestriction {
    #[getter]
    fn audiences(&self) -> Vec<String> {
        self.inner.audiences.clone()
    }
    fn matches(&self, entity_id: &str) -> bool {
        self.inner.matches(entity_id)
    }
}

#[pymethods]
impl ProxyRestriction {
    #[getter]
    fn count(&self) -> Option<u32> {
        self.inner.count
    }
    #[getter]
    fn audiences(&self) -> Vec<String> {
        self.inner.audiences.clone()
    }
}

#[pymethods]
impl Conditions {
    #[getter]
    fn not_before(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.inner.not_before
    }
    #[getter]
    fn not_on_or_after(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.inner.not_on_or_after
    }
    #[getter]
    fn one_time_use(&self) -> bool {
        self.inner.one_time_use
    }
    #[getter]
    fn audience_restrictions(&self) -> Vec<AudienceRestriction> {
        self.inner
            .audience_restrictions
            .iter()
            .cloned()
            .map(AudienceRestriction::wrap)
            .collect()
    }
    #[getter]
    fn proxy_restriction(&self) -> Option<ProxyRestriction> {
        self.inner
            .proxy_restriction
            .clone()
            .map(ProxyRestriction::wrap)
    }
}

// ---------------------------------------------------------------------------
// AuthnContext / AuthnStatement
// ---------------------------------------------------------------------------

#[pymethods]
impl SubjectLocality {
    #[getter]
    fn address(&self) -> Option<&str> {
        self.inner.address.as_deref()
    }
    #[getter]
    fn dns_name(&self) -> Option<&str> {
        self.inner.dns_name.as_deref()
    }
}

#[pymethods]
impl AuthnContext {
    #[getter]
    fn authn_context_class_ref(&self) -> Option<&str> {
        self.inner.authn_context_class_ref.as_deref()
    }
    #[getter]
    fn authn_context_decl_ref(&self) -> Option<&str> {
        self.inner.authn_context_decl_ref.as_deref()
    }
    #[getter]
    fn authenticating_authorities(&self) -> Vec<String> {
        self.inner.authenticating_authorities.clone()
    }
}

#[pymethods]
impl AuthnStatement {
    #[getter]
    fn authn_instant(&self) -> chrono::DateTime<chrono::Utc> {
        self.inner.authn_instant
    }
    #[getter]
    fn session_index(&self) -> Option<&str> {
        self.inner.session_index.as_deref()
    }
    #[getter]
    fn session_not_on_or_after(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.inner.session_not_on_or_after
    }
    #[getter]
    fn subject_locality(&self) -> Option<SubjectLocality> {
        self.inner
            .subject_locality
            .clone()
            .map(SubjectLocality::wrap)
    }
    #[getter]
    fn authn_context(&self) -> AuthnContext {
        AuthnContext::wrap(self.inner.authn_context.clone())
    }
}

// ---------------------------------------------------------------------------
// Attribute / AttributeStatement
// ---------------------------------------------------------------------------

#[pymethods]
impl Attribute {
    #[new]
    #[pyo3(signature = (name, values=None, name_format=None, friendly_name=None))]
    fn new(
        name: String,
        values: Option<Vec<String>>,
        name_format: Option<String>,
        friendly_name: Option<String>,
    ) -> Self {
        let values = values
            .unwrap_or_default()
            .into_iter()
            .map(ga::AttributeValue::String)
            .collect();
        Attribute::wrap(ga::Attribute {
            name,
            name_format,
            friendly_name,
            values,
        })
    }
    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }
    #[getter]
    fn name_format(&self) -> Option<&str> {
        self.inner.name_format.as_deref()
    }
    #[getter]
    fn friendly_name(&self) -> Option<&str> {
        self.inner.friendly_name.as_deref()
    }
    /// All values as native Python objects (str/int/bool/bytes/NameId).
    #[getter]
    fn values(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        let list = PyList::empty(py);
        for v in &self.inner.values {
            list.append(attr_value_to_py(py, v)?)?;
        }
        Ok(list.unbind())
    }
    /// Only the string-typed values, as a list[str] (convenience for SATOSA AVA).
    #[getter]
    fn string_values(&self) -> Vec<String> {
        self.inner
            .values
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    }
    fn __repr__(&self) -> String {
        format!(
            "Attribute(name={:?}, values={})",
            self.inner.name,
            self.inner.values.len()
        )
    }
}

#[pymethods]
impl AttributeStatement {
    #[getter]
    fn attributes(&self) -> Vec<Attribute> {
        self.inner
            .attributes
            .iter()
            .cloned()
            .map(Attribute::wrap)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

#[pymethods]
impl StatusCode {
    #[getter]
    fn value(&self) -> &str {
        &self.inner.value
    }
    #[getter]
    fn sub_status(&self) -> Option<StatusCode> {
        self.inner
            .sub_status
            .as_ref()
            .map(|b| StatusCode::wrap((**b).clone()))
    }
    fn is_success(&self) -> bool {
        self.inner.is_success()
    }
}

#[pymethods]
impl Status {
    #[getter]
    fn status_code(&self) -> StatusCode {
        StatusCode::wrap(self.inner.status_code.clone())
    }
    #[getter]
    fn status_message(&self) -> Option<&str> {
        self.inner.status_message.as_deref()
    }
    #[getter]
    fn status_detail(&self) -> Option<&str> {
        self.inner.status_detail.as_deref()
    }
    fn is_success(&self) -> bool {
        self.inner.is_success()
    }
}

// ---------------------------------------------------------------------------
// Assertion
// ---------------------------------------------------------------------------

#[pymethods]
impl Assertion {
    #[getter]
    fn id(&self) -> &str {
        &self.inner.id
    }
    #[getter]
    fn issue_instant(&self) -> chrono::DateTime<chrono::Utc> {
        self.inner.issue_instant
    }
    #[getter]
    fn issuer(&self) -> Issuer {
        Issuer::wrap(self.inner.issuer.clone())
    }
    #[getter]
    fn has_signature(&self) -> bool {
        self.inner.has_signature
    }
    #[getter]
    fn subject(&self) -> Option<Subject> {
        self.inner.subject.clone().map(Subject::wrap)
    }
    #[getter]
    fn conditions(&self) -> Option<Conditions> {
        self.inner.conditions.clone().map(Conditions::wrap)
    }
    #[getter]
    fn authn_statements(&self) -> Vec<AuthnStatement> {
        self.inner
            .authn_statements
            .iter()
            .cloned()
            .map(AuthnStatement::wrap)
            .collect()
    }
    #[getter]
    fn attribute_statements(&self) -> Vec<AttributeStatement> {
        self.inner
            .attribute_statements
            .iter()
            .cloned()
            .map(AttributeStatement::wrap)
            .collect()
    }
    fn __repr__(&self) -> String {
        format!("Assertion(id={:?})", self.inner.id)
    }
}

// ---------------------------------------------------------------------------
// Protocol: AuthnRequest / Response / Logout
// ---------------------------------------------------------------------------

#[pymethods]
impl RequestedAuthnContext {
    #[getter]
    fn authn_context_class_refs(&self) -> Vec<String> {
        self.inner.authn_context_class_refs.clone()
    }
    #[getter]
    fn comparison(&self) -> String {
        self.inner.comparison.as_str().to_string()
    }
}

#[pymethods]
impl Scoping {
    #[getter]
    fn proxy_count(&self) -> Option<u32> {
        self.inner.proxy_count
    }
    #[getter]
    fn idp_list(&self) -> Vec<String> {
        self.inner.idp_list.clone()
    }
    #[getter]
    fn requester_ids(&self) -> Vec<String> {
        self.inner.requester_ids.clone()
    }
}

#[pymethods]
impl AuthnRequest {
    #[getter]
    fn id(&self) -> &str {
        &self.inner.base.id
    }
    #[getter]
    fn issue_instant(&self) -> chrono::DateTime<chrono::Utc> {
        self.inner.base.issue_instant
    }
    #[getter]
    fn destination(&self) -> Option<&str> {
        self.inner.base.destination.as_deref()
    }
    #[getter]
    fn issuer(&self) -> Option<Issuer> {
        self.inner.base.issuer.clone().map(Issuer::wrap)
    }
    #[getter]
    fn has_signature(&self) -> bool {
        self.inner.base.has_signature
    }
    #[getter]
    fn name_id_policy(&self) -> Option<NameIdPolicy> {
        self.inner.name_id_policy.clone().map(NameIdPolicy::wrap)
    }
    #[getter]
    fn requested_authn_context(&self) -> Option<RequestedAuthnContext> {
        self.inner
            .requested_authn_context
            .clone()
            .map(RequestedAuthnContext::wrap)
    }
    #[getter]
    fn scoping(&self) -> Option<Scoping> {
        self.inner.scoping.clone().map(Scoping::wrap)
    }
    #[getter]
    fn force_authn(&self) -> Option<bool> {
        self.inner.force_authn
    }
    #[getter]
    fn is_passive(&self) -> Option<bool> {
        self.inner.is_passive
    }
    #[getter]
    fn assertion_consumer_service_url(&self) -> Option<&str> {
        self.inner.assertion_consumer_service_url.as_deref()
    }
    #[getter]
    fn protocol_binding(&self) -> Option<&str> {
        self.inner.protocol_binding.as_deref()
    }
    #[getter]
    fn provider_name(&self) -> Option<&str> {
        self.inner.provider_name.as_deref()
    }
    /// Serialize to a SAML XML string (without enveloped signature).
    fn to_xml(&self) -> PyResult<String> {
        use gamlastan::xml::SamlSerialize;
        self.inner.to_xml_string().map_err(crate::errors::xml_err)
    }
    fn __repr__(&self) -> String {
        format!("AuthnRequest(id={:?})", self.inner.base.id)
    }
}

#[pymethods]
impl Response {
    #[getter]
    fn id(&self) -> &str {
        &self.inner.base.id
    }
    #[getter]
    fn issue_instant(&self) -> chrono::DateTime<chrono::Utc> {
        self.inner.base.issue_instant
    }
    #[getter]
    fn destination(&self) -> Option<&str> {
        self.inner.base.destination.as_deref()
    }
    #[getter]
    fn in_response_to(&self) -> Option<&str> {
        self.inner.base.in_response_to.as_deref()
    }
    #[getter]
    fn issuer(&self) -> Option<Issuer> {
        self.inner.base.issuer.clone().map(Issuer::wrap)
    }
    #[getter]
    fn has_signature(&self) -> bool {
        self.inner.base.has_signature
    }
    #[getter]
    fn status(&self) -> Status {
        Status::wrap(self.inner.base.status.clone())
    }
    fn is_success(&self) -> bool {
        self.inner.base.status.is_success()
    }
    #[getter]
    fn assertions(&self) -> Vec<Assertion> {
        self.inner
            .assertions
            .iter()
            .cloned()
            .map(Assertion::wrap)
            .collect()
    }
    #[getter]
    fn encrypted_assertion_count(&self) -> usize {
        self.inner.encrypted_assertions.len()
    }
    fn to_xml(&self) -> PyResult<String> {
        use gamlastan::xml::SamlSerialize;
        self.inner.to_xml_string().map_err(crate::errors::xml_err)
    }
    fn __repr__(&self) -> String {
        format!(
            "Response(id={:?}, success={})",
            self.inner.base.id,
            self.inner.base.status.is_success()
        )
    }
}

#[pymethods]
impl LogoutRequest {
    #[getter]
    fn id(&self) -> &str {
        &self.inner.id
    }
    #[getter]
    fn issue_instant(&self) -> chrono::DateTime<chrono::Utc> {
        self.inner.issue_instant
    }
    #[getter]
    fn destination(&self) -> Option<&str> {
        self.inner.destination.as_deref()
    }
    #[getter]
    fn issuer(&self) -> Option<Issuer> {
        self.inner.issuer.clone().map(Issuer::wrap)
    }
    #[getter]
    fn reason(&self) -> Option<&str> {
        self.inner.reason.as_deref()
    }
    #[getter]
    fn name_id(&self) -> Option<NameId> {
        match &self.inner.name_id {
            ga::NameIdOrEncryptedId::NameId(n) => Some(NameId::wrap(n.clone())),
            _ => None,
        }
    }
    #[getter]
    fn session_indexes(&self) -> Vec<String> {
        self.inner.session_indexes.clone()
    }
    fn to_xml(&self) -> PyResult<String> {
        use gamlastan::xml::SamlSerialize;
        self.inner.to_xml_string().map_err(crate::errors::xml_err)
    }
}

#[pymethods]
impl LogoutResponse {
    #[getter]
    fn id(&self) -> &str {
        &self.inner.id
    }
    #[getter]
    fn in_response_to(&self) -> Option<&str> {
        self.inner.in_response_to.as_deref()
    }
    #[getter]
    fn issuer(&self) -> Option<Issuer> {
        self.inner.issuer.clone().map(Issuer::wrap)
    }
    #[getter]
    fn status(&self) -> Status {
        Status::wrap(self.inner.status.clone())
    }
    fn is_success(&self) -> bool {
        self.inner.status.is_success()
    }
    fn to_xml(&self) -> PyResult<String> {
        use gamlastan::xml::SamlSerialize;
        self.inner.to_xml_string().map_err(crate::errors::xml_err)
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Generate a fresh, random SAML ID (NCName, suitable for message/assertion IDs).
#[pyfunction]
fn generate_id() -> String {
    gamlastan::core::SamlId::generate().as_str().to_string()
}

/// Validate an entity id (length / non-empty), returning the normalized string.
#[pyfunction]
fn validate_entity_id(value: &str) -> PyResult<String> {
    gamlastan::core::EntityId::new(value)
        .map(|e| e.as_str().to_string())
        .map_err(core_err)
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

macro_rules! add_const {
    ($m:ident, $name:literal, $val:expr) => {
        $m.add($name, $val)?;
    };
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "core")?;

    m.add_class::<Issuer>()?;
    m.add_class::<NameId>()?;
    m.add_class::<NameIdPolicy>()?;
    m.add_class::<SubjectConfirmationData>()?;
    m.add_class::<SubjectConfirmation>()?;
    m.add_class::<Subject>()?;
    m.add_class::<AudienceRestriction>()?;
    m.add_class::<ProxyRestriction>()?;
    m.add_class::<Conditions>()?;
    m.add_class::<SubjectLocality>()?;
    m.add_class::<AuthnContext>()?;
    m.add_class::<AuthnStatement>()?;
    m.add_class::<Attribute>()?;
    m.add_class::<AttributeStatement>()?;
    m.add_class::<Assertion>()?;
    m.add_class::<StatusCode>()?;
    m.add_class::<Status>()?;
    m.add_class::<RequestedAuthnContext>()?;
    m.add_class::<Scoping>()?;
    m.add_class::<AuthnRequest>()?;
    m.add_class::<Response>()?;
    m.add_class::<LogoutRequest>()?;
    m.add_class::<LogoutResponse>()?;
    m.add_function(wrap_pyfunction!(generate_id, &m)?)?;
    m.add_function(wrap_pyfunction!(validate_entity_id, &m)?)?;

    // Binding URIs
    add_const!(m, "BINDING_SOAP", gc::BINDING_SOAP);
    add_const!(m, "BINDING_PAOS", gc::BINDING_PAOS);
    add_const!(m, "BINDING_HTTP_REDIRECT", gc::BINDING_HTTP_REDIRECT);
    add_const!(m, "BINDING_HTTP_POST", gc::BINDING_HTTP_POST);
    add_const!(m, "BINDING_HTTP_ARTIFACT", gc::BINDING_HTTP_ARTIFACT);
    add_const!(m, "BINDING_URI", gc::BINDING_URI);

    // NameID formats
    add_const!(m, "NAMEID_UNSPECIFIED", gc::NAMEID_UNSPECIFIED);
    add_const!(m, "NAMEID_EMAIL", gc::NAMEID_EMAIL);
    add_const!(m, "NAMEID_X509", gc::NAMEID_X509);
    add_const!(m, "NAMEID_WINDOWS", gc::NAMEID_WINDOWS);
    add_const!(m, "NAMEID_ENTITY", gc::NAMEID_ENTITY);
    add_const!(m, "NAMEID_PERSISTENT", gc::NAMEID_PERSISTENT);
    add_const!(m, "NAMEID_TRANSIENT", gc::NAMEID_TRANSIENT);
    add_const!(m, "NAMEID_KERBEROS", gc::NAMEID_KERBEROS);
    add_const!(m, "NAMEID_ENCRYPTED", gc::NAMEID_ENCRYPTED);

    // Confirmation methods
    add_const!(m, "CM_BEARER", gc::CM_BEARER);
    add_const!(m, "CM_HOLDER_OF_KEY", gc::CM_HOLDER_OF_KEY);
    add_const!(m, "CM_SENDER_VOUCHES", gc::CM_SENDER_VOUCHES);

    // Status codes
    add_const!(m, "STATUS_SUCCESS", gc::STATUS_SUCCESS);
    add_const!(m, "STATUS_REQUESTER", gc::STATUS_REQUESTER);
    add_const!(m, "STATUS_RESPONDER", gc::STATUS_RESPONDER);
    add_const!(m, "STATUS_VERSION_MISMATCH", gc::STATUS_VERSION_MISMATCH);
    add_const!(m, "STATUS_AUTHN_FAILED", gc::STATUS_AUTHN_FAILED);
    add_const!(m, "STATUS_NO_AUTHN_CONTEXT", gc::STATUS_NO_AUTHN_CONTEXT);
    add_const!(m, "STATUS_REQUEST_DENIED", gc::STATUS_REQUEST_DENIED);
    add_const!(m, "STATUS_UNKNOWN_PRINCIPAL", gc::STATUS_UNKNOWN_PRINCIPAL);

    // Authn context classes
    add_const!(m, "AUTHN_CONTEXT_PASSWORD", gc::AUTHN_CONTEXT_PASSWORD);
    add_const!(
        m,
        "AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT",
        gc::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
    );
    add_const!(
        m,
        "AUTHN_CONTEXT_UNSPECIFIED",
        gc::AUTHN_CONTEXT_UNSPECIFIED
    );
    add_const!(m, "AUTHN_CONTEXT_X509", gc::AUTHN_CONTEXT_X509);
    add_const!(m, "AUTHN_CONTEXT_KERBEROS", gc::AUTHN_CONTEXT_KERBEROS);

    // Attribute name formats
    add_const!(
        m,
        "ATTRNAME_FORMAT_UNSPECIFIED",
        gc::ATTRNAME_FORMAT_UNSPECIFIED
    );
    add_const!(m, "ATTRNAME_FORMAT_URI", gc::ATTRNAME_FORMAT_URI);
    add_const!(m, "ATTRNAME_FORMAT_BASIC", gc::ATTRNAME_FORMAT_BASIC);

    // Namespaces
    add_const!(m, "SAML_ASSERTION_NS", gn::SAML_ASSERTION_NS);
    add_const!(m, "SAML_PROTOCOL_NS", gn::SAML_PROTOCOL_NS);
    add_const!(m, "SAML_METADATA_NS", gn::SAML_METADATA_NS);
    add_const!(m, "XMLDSIG_NS", gn::XMLDSIG_NS);
    add_const!(m, "XMLENC_NS", gn::XMLENC_NS);

    Ok(())
}
