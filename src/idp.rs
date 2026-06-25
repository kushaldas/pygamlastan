//! Bindings for `gamlastan::idp` - IdP-side infrastructure: eduPersonTargetedID
//! generation, the authentication broker, NameID storage coding, and an
//! issued-assertion store.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use gamlastan::idp as gi;

use crate::convert::new_submodule;
use crate::core::{Assertion, Attribute, NameId, RequestedAuthnContext};

// ---------------------------------------------------------------------------
// Eptid (eduPersonTargetedID)
// ---------------------------------------------------------------------------

// `gi::Eptid` is generic over an `IdentityStore`, defaulting to the in-memory
// one (`Eptid<InMemoryIdentityStore>`). We bind only that default; eduPerson
// TargetedID is a pure hash of (secret, idp, sp, user) and does not require a
// persistent store for derivation, so the default is sufficient here.
#[pyclass(module = "pygamlastan.idp", name = "Eptid")]
pub struct Eptid {
    inner: gi::Eptid,
}

#[pymethods]
impl Eptid {
    /// Create with a server-side secret used to derive opaque, per-SP IDs.
    #[new]
    fn new(secret: String) -> Self {
        Eptid { inner: gi::Eptid::new(secret) }
    }
    /// The opaque persistent identifier string for (idp, sp, user).
    fn get(&self, idp_entity_id: &str, sp_entity_id: &str, user_id: &str) -> String {
        self.inner.get(idp_entity_id, sp_entity_id, user_id)
    }
    /// The identifier as a persistent NameID.
    fn name_id(&self, idp_entity_id: &str, sp_entity_id: &str, user_id: &str) -> NameId {
        NameId::wrap(self.inner.name_id(idp_entity_id, sp_entity_id, user_id))
    }
    /// The identifier as an eduPersonTargetedID attribute.
    fn attribute(&self, idp_entity_id: &str, sp_entity_id: &str, user_id: &str) -> Attribute {
        Attribute::wrap(self.inner.attribute(idp_entity_id, sp_entity_id, user_id))
    }
}

// ---------------------------------------------------------------------------
// AuthnBroker / AuthnMethod
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.idp", name = "AuthnMethod", frozen)]
pub struct AuthnMethod {
    #[pyo3(get)]
    class_ref: String,
    #[pyo3(get)]
    method: String,
    #[pyo3(get)]
    level: u32,
    #[pyo3(get)]
    authn_authority: Option<String>,
    #[pyo3(get)]
    reference: String,
}

fn method_to_py(m: &gi::AuthnMethod) -> AuthnMethod {
    AuthnMethod {
        class_ref: m.class_ref.clone(),
        method: m.method.clone(),
        level: m.level,
        authn_authority: m.authn_authority.clone(),
        reference: m.reference.clone(),
    }
}

#[pyclass(module = "pygamlastan.idp", name = "AuthnBroker")]
pub struct AuthnBroker {
    inner: gi::AuthnBroker,
}

#[pymethods]
impl AuthnBroker {
    #[new]
    fn new() -> Self {
        AuthnBroker { inner: gi::AuthnBroker::new() }
    }
    /// Register an authentication method; returns its reference.
    #[pyo3(signature = (class_ref, method, level, authn_authority=None))]
    fn add(&mut self, class_ref: &str, method: &str, level: u32, authn_authority: Option<&str>) -> String {
        self.inner.add(class_ref, method, level, authn_authority)
    }
    fn get_by_class_ref(&self, class_ref: &str) -> Option<AuthnMethod> {
        self.inner.get_by_class_ref(class_ref).map(method_to_py)
    }
    /// Methods matching a RequestedAuthnContext (or all, if None), best first.
    #[pyo3(signature = (requested=None))]
    fn pick(&self, requested: Option<&RequestedAuthnContext>) -> Vec<AuthnMethod> {
        let req = requested.map(|r| &r.inner);
        self.inner.pick(req).into_iter().map(method_to_py).collect()
    }
}

// ---------------------------------------------------------------------------
// Assertion store (built-in)
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.idp", name = "InMemoryAssertionStore")]
pub struct InMemoryAssertionStore {
    inner: gi::InMemoryAssertionStore,
}

#[pymethods]
impl InMemoryAssertionStore {
    #[new]
    fn new() -> Self {
        InMemoryAssertionStore { inner: gi::InMemoryAssertionStore::new() }
    }
    // The store methods are inherent on the gamlastan type only via the
    // `AssertionStore` trait, so each call brings the trait into scope with a
    // local `use` (cheaper than a module-level import that would look unused to
    // readers scanning the top of the file).
    fn store_assertion(&self, assertion: &Assertion) {
        use gi::AssertionStore;
        self.inner.store_assertion(assertion.inner.clone());
    }
    fn get_assertion(&self, assertion_id: &str) -> Option<Assertion> {
        use gi::AssertionStore;
        self.inner.get_assertion(assertion_id).map(Assertion::wrap)
    }
    fn assertions_for_subject(&self, name_id_value: &str) -> Vec<Assertion> {
        use gi::AssertionStore;
        self.inner.assertions_for_subject(name_id_value).into_iter().map(Assertion::wrap).collect()
    }
    fn remove_assertion(&self, assertion_id: &str) {
        use gi::AssertionStore;
        self.inner.remove_assertion(assertion_id);
    }
}

// ---------------------------------------------------------------------------
// NameID storage coding
// ---------------------------------------------------------------------------

/// Serialize a NameID to its storage form.
#[pyfunction]
fn code_name_id(name_id: &NameId) -> String {
    gi::ident::code_name_id(&name_id.inner)
}

/// Parse a NameID from its storage form.
#[pyfunction]
fn decode_name_id(coded: &str) -> NameId {
    NameId::wrap(gi::ident::decode_name_id(coded))
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "idp")?;
    m.add_class::<Eptid>()?;
    m.add_class::<AuthnBroker>()?;
    m.add_class::<AuthnMethod>()?;
    m.add_class::<InMemoryAssertionStore>()?;
    m.add_function(wrap_pyfunction!(code_name_id, &m)?)?;
    m.add_function(wrap_pyfunction!(decode_name_id, &m)?)?;
    Ok(())
}
