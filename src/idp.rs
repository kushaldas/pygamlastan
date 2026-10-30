//! Bindings for `gamlastan::idp` - IdP-side infrastructure: eduPersonTargetedID
//! generation, the authentication broker, NameID storage coding, and an
//! issued-assertion store.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use chrono::{DateTime, TimeDelta, Utc};

use gamlastan::core::assertion::NameId as GNameId;
use gamlastan::core::constants;
use gamlastan::core::protocol::name_id_mgmt::NewIdOrTerminate;
use gamlastan::idp as gi;
use gamlastan::idp::entity_category as gec;
use gamlastan::idp::ident::{
    IdentError, IdentityStore, InMemoryIdentityStore, InsertError, StoreError,
};
use gamlastan::idp::policy as gpol;
use gamlastan::metadata::types::sp::RequestedAttribute;

use crate::convert::new_submodule;
use crate::core::{Assertion, Attribute, NameId, NameIdPolicy, RequestedAuthnContext};
use crate::errors::{ident_err, policy_err, store_err, NameIdDurableExists, NameIdValueTaken};
use crate::metadata::EntityDescriptor;
use crate::signing::SigningPreference;

// ---------------------------------------------------------------------------
// Eptid (eduPersonTargetedID)
// ---------------------------------------------------------------------------

// `gi::Eptid` is generic over a `KeyValueStore` that caches derived values,
// defaulting to the in-memory one (`Eptid<InMemoryKeyValueStore>`). We bind
// only that default: values are derived deterministically from (secret, idp,
// sp, user), so a fresh instance reproduces them. Known gap: no pluggable
// Python store, so existing pysaml2 EPTID mappings (shelve/Mongo) cannot be
// imported; that only matters for hand-edited or imported values. Add a
// `PyKeyValueStore` adapter (same pattern as `PyIdentityStore`) if needed.
#[pyclass(module = "pygamlastan.idp", name = "Eptid")]
pub struct Eptid {
    inner: gi::Eptid,
}

#[pymethods]
impl Eptid {
    /// Create with a server-side secret used to derive opaque, per-SP IDs.
    ///
    /// `digest` is `"sha256"` (default) or `"pysaml2-md5"`, which reproduces
    /// stock pysaml2's `idp!sp!md5(user+sp+secret)` values so SPs that key
    /// accounts on the EPTID keep seeing the same value after a migration.
    /// MD5 is only accepted with `allow_legacy_md5=True`.
    #[new]
    #[pyo3(signature = (secret, digest="sha256", allow_legacy_md5=false))]
    fn new(secret: String, digest: &str, allow_legacy_md5: bool) -> PyResult<Self> {
        let options = match digest {
            "sha256" => gi::eptid::EptidOptions::sha256(),
            "pysaml2-md5" => gi::eptid::EptidOptions::pysaml2_md5_legacy(allow_legacy_md5),
            other => {
                return Err(ident_err(format!(
                    "unknown EPTID digest {other:?} (known: sha256, pysaml2-md5)"
                )))
            }
        };
        let inner = gi::Eptid::try_new_with_options(secret, options).map_err(ident_err)?;
        Ok(Eptid { inner })
    }
    /// The opaque persistent identifier string for (idp, sp, user).
    fn get(&self, idp_entity_id: &str, sp_entity_id: &str, user_id: &str) -> PyResult<String> {
        self.inner
            .get(idp_entity_id, sp_entity_id, user_id)
            .map_err(store_err)
    }
    /// The identifier as a persistent NameID.
    fn name_id(&self, idp_entity_id: &str, sp_entity_id: &str, user_id: &str) -> PyResult<NameId> {
        self.inner
            .name_id(idp_entity_id, sp_entity_id, user_id)
            .map(NameId::wrap)
            .map_err(store_err)
    }
    /// The identifier as an eduPersonTargetedID attribute.
    fn attribute(
        &self,
        idp_entity_id: &str,
        sp_entity_id: &str,
        user_id: &str,
    ) -> PyResult<Attribute> {
        self.inner
            .attribute(idp_entity_id, sp_entity_id, user_id)
            .map(Attribute::wrap)
            .map_err(store_err)
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

pub(crate) fn method_to_py(m: &gi::AuthnMethod) -> AuthnMethod {
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
    pub(crate) inner: gi::AuthnBroker,
}

#[pymethods]
impl AuthnBroker {
    /// Create an empty broker.
    ///
    /// ``allow_exact_level_matching=True`` restores pysaml2's looser
    /// ``Comparison="exact"``: any method registered at the same security level
    /// as a requested class counts, not only a literal class-ref match
    /// (saml-core-2.0-os 3.3.2.2.1). The default is the literal match.
    #[new]
    #[pyo3(signature = (allow_exact_level_matching=false))]
    fn new(allow_exact_level_matching: bool) -> Self {
        AuthnBroker {
            inner: gi::AuthnBroker::new().allow_exact_level_matching(allow_exact_level_matching),
        }
    }
    /// Whether no method is registered. With an empty broker an ``exact``
    /// request is left to the response-time check (an inline method is
    /// accepted if its class ref matches literally); the other comparisons need
    /// the broker's strength ordering and are denied before login.
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    /// Register an authentication method; returns its reference.
    #[pyo3(signature = (class_ref, method, level, authn_authority=None))]
    fn add(
        &mut self,
        class_ref: &str,
        method: &str,
        level: u32,
        authn_authority: Option<&str>,
    ) -> String {
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
    pub(crate) inner: gi::InMemoryAssertionStore,
}

#[pymethods]
impl InMemoryAssertionStore {
    #[new]
    fn new() -> Self {
        InMemoryAssertionStore {
            inner: gi::InMemoryAssertionStore::new(),
        }
    }
    // The store methods are inherent on the gamlastan type only via the
    // `AssertionStore` trait, so each call brings the trait into scope with a
    // local `use` (cheaper than a module-level import that would look unused to
    // readers scanning the top of the file).
    fn store_assertion(&self, assertion: &Assertion) -> PyResult<()> {
        use gi::AssertionStore;
        self.inner
            .store_assertion(assertion.inner.clone())
            .map_err(store_err)
    }
    fn get_assertion(&self, assertion_id: &str) -> PyResult<Option<Assertion>> {
        use gi::AssertionStore;
        self.inner
            .get_assertion(assertion_id)
            .map(|a| a.map(Assertion::wrap))
            .map_err(store_err)
    }
    fn assertions_for_subject(&self, name_id_value: &str) -> PyResult<Vec<Assertion>> {
        use gi::AssertionStore;
        self.inner
            .assertions_for_subject(name_id_value)
            .map(|v| v.into_iter().map(Assertion::wrap).collect())
            .map_err(store_err)
    }
    fn remove_assertion(&self, assertion_id: &str) -> PyResult<()> {
        use gi::AssertionStore;
        self.inner.remove_assertion(assertion_id).map_err(store_err)
    }
}

// ---------------------------------------------------------------------------
// IdentDb (NameID database, pysaml2 IdentDB)
// ---------------------------------------------------------------------------

/// Adapter implementing the Rust `IdentityStore` trait by calling into a Python
/// object. The object provides one single-record method per trait method
/// (NameIDs cross the boundary as `pygamlastan.core.NameId`):
///
/// * `for_user(user_id) -> list[NameId]`
/// * `user_for(value) -> str | None`
/// * `get_or_insert_durable(user_id, candidate) -> NameId`
/// * `insert(user_id, name_id)`, `replace(user_id, name_id)`
/// * `remove(value)`, `remove_all(user_id)`
///
/// `find` and `find_durable` are optional and default to filtering `for_user`.
///
/// Atomicity comes from two unique constraints the backend must enforce (see
/// `IdentityStore`). A backend signals a conflict by raising `NameIdValueTaken`
/// or `NameIdDurableExists`; any other exception is a backend failure and
/// surfaces as `SamlStoreError`, never as "no record".
pub(crate) struct PyIdentityStore {
    obj: Py<PyAny>,
}

fn py_store_err(e: PyErr) -> StoreError {
    StoreError::new(e)
}

fn py_insert_err(py: Python<'_>, e: PyErr) -> InsertError {
    if e.is_instance_of::<NameIdValueTaken>(py) {
        InsertError::ValueTaken
    } else if e.is_instance_of::<NameIdDurableExists>(py) {
        InsertError::DurableExists
    } else {
        InsertError::Store(py_store_err(e))
    }
}

fn nid_to_py(py: Python<'_>, n: GNameId) -> PyResult<Py<NameId>> {
    Py::new(py, NameId::wrap(n))
}

fn nid_from_py(obj: &Bound<'_, PyAny>) -> PyResult<GNameId> {
    Ok(obj.extract::<NameId>()?.inner)
}

/// Whether `n` is a durable NameID of `format` with exactly these qualifiers.
/// Transient is never durable, and an absent format is `unspecified`
/// (mirrors gamlastan's own check, which is crate-private).
fn is_durable_match(
    n: &GNameId,
    sp_name_qualifier: Option<&str>,
    name_qualifier: Option<&str>,
    format: &str,
) -> bool {
    format != constants::NAMEID_TRANSIENT
        && n.format.as_deref().unwrap_or(constants::NAMEID_UNSPECIFIED) == format
        && n.sp_name_qualifier.as_deref() == sp_name_qualifier
        && n.name_qualifier.as_deref() == name_qualifier
}

impl PyIdentityStore {
    pub(crate) fn new(obj: Py<PyAny>) -> Self {
        PyIdentityStore { obj }
    }

    /// Refuse a record a Python backend returned for `user_id` unless it is that
    /// user's own. The backend is the part of the system least under our
    /// control: a `find_durable` that forgot the user in its filter, a wrong
    /// index or a stale cache would otherwise hand one user another user's
    /// persistent NameID, with nothing written to betray it. That is account
    /// takeover at every SP that has seen the value, so it is checked here,
    /// where the gamlastan core cannot see the backend.
    ///
    /// `slot` is the `(SPNameQualifier, NameQualifier, format)` the lookup asked
    /// for; the record must be exactly that durable slot, and the store must
    /// attribute its value to `user_id`.
    fn verify_own_record(
        &self,
        user_id: &str,
        record: &GNameId,
        slot: (Option<&str>, Option<&str>, &str),
        call: &str,
    ) -> Result<(), StoreError> {
        let (spq, nq, format) = slot;
        if !is_durable_match(record, spq, nq, format) {
            return Err(StoreError::new(format!(
                "the backend's {call} returned a record that is not the durable NameID \
                 requested (format {format:?}, SPNameQualifier {spq:?}, NameQualifier \
                 {nq:?}); refusing to use it"
            )));
        }
        match self.user_for(&record.value)? {
            Some(owner) if owner == user_id => Ok(()),
            _ => Err(StoreError::new(format!(
                "the backend's {call} returned a NameID that the store does not attribute \
                 to this user; refusing to use it"
            ))),
        }
    }

    fn names(py: Python<'_>, r: Bound<'_, PyAny>) -> PyResult<Vec<GNameId>> {
        let _ = py;
        r.try_iter()?.map(|i| nid_from_py(&i?)).collect()
    }
}

impl IdentityStore for PyIdentityStore {
    fn for_user(&self, user_id: &str) -> Result<Vec<GNameId>, StoreError> {
        Python::attach(|py| {
            let r = self.obj.bind(py).call_method1("for_user", (user_id,))?;
            Self::names(py, r)
        })
        .map_err(py_store_err)
    }

    fn user_for(&self, value: &str) -> Result<Option<String>, StoreError> {
        Python::attach(|py| {
            self.obj
                .bind(py)
                .call_method1("user_for", (value,))?
                .extract::<Option<String>>()
        })
        .map_err(py_store_err)
    }

    fn find_durable(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
        format: &str,
    ) -> Result<Option<GNameId>, StoreError> {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            if !obj.hasattr("find_durable")? {
                return Ok(None::<Option<GNameId>>);
            }
            let r = obj.call_method1(
                "find_durable",
                (user_id, sp_name_qualifier, name_qualifier, format),
            )?;
            if r.is_none() {
                Ok(Some(None))
            } else {
                Ok(Some(Some(nid_from_py(&r)?)))
            }
        })
        .map_err(py_store_err)
        .and_then(|r| match r {
            Some(found) => {
                if let Some(record) = &found {
                    self.verify_own_record(
                        user_id,
                        record,
                        (sp_name_qualifier, name_qualifier, format),
                        "find_durable",
                    )?;
                }
                Ok(found)
            }
            // No pushed-down lookup on the backend: filter `for_user`.
            None => Ok(self
                .for_user(user_id)?
                .into_iter()
                .find(|n| is_durable_match(n, sp_name_qualifier, name_qualifier, format))),
        })
    }

    fn get_or_insert_durable(
        &self,
        user_id: &str,
        candidate: GNameId,
    ) -> Result<GNameId, InsertError> {
        // What the caller asked for, kept to check the answer against. A
        // transient candidate has no uniqueness slot (it is a plain insert), so
        // only a durable one is checked.
        let slot = (
            candidate.sp_name_qualifier.clone(),
            candidate.name_qualifier.clone(),
            candidate
                .format
                .clone()
                .unwrap_or_else(|| constants::NAMEID_UNSPECIFIED.to_string()),
        );
        let durable = slot.2 != constants::NAMEID_TRANSIENT;
        let record = Python::attach(|py| {
            let c = nid_to_py(py, candidate).map_err(|e| py_insert_err(py, e))?;
            let r = self
                .obj
                .bind(py)
                .call_method1("get_or_insert_durable", (user_id, c))
                .map_err(|e| py_insert_err(py, e))?;
            nid_from_py(&r).map_err(|e| py_insert_err(py, e))
        })?;
        if durable {
            self.verify_own_record(
                user_id,
                &record,
                (slot.0.as_deref(), slot.1.as_deref(), &slot.2),
                "get_or_insert_durable",
            )
            .map_err(InsertError::Store)?;
        }
        Ok(record)
    }

    fn insert(&self, user_id: &str, name_id: GNameId) -> Result<(), InsertError> {
        Python::attach(|py| {
            let n = nid_to_py(py, name_id).map_err(|e| py_insert_err(py, e))?;
            self.obj
                .bind(py)
                .call_method1("insert", (user_id, n))
                .map(drop)
                .map_err(|e| py_insert_err(py, e))
        })
    }

    fn replace(&self, user_id: &str, name_id: GNameId) -> Result<(), InsertError> {
        Python::attach(|py| {
            let n = nid_to_py(py, name_id).map_err(|e| py_insert_err(py, e))?;
            self.obj
                .bind(py)
                .call_method1("replace", (user_id, n))
                .map(drop)
                .map_err(|e| py_insert_err(py, e))
        })
    }

    fn remove(&self, value: &str) -> Result<(), StoreError> {
        Python::attach(|py| self.obj.bind(py).call_method1("remove", (value,)).map(drop))
            .map_err(py_store_err)
    }

    fn remove_all(&self, user_id: &str) -> Result<(), StoreError> {
        Python::attach(|py| {
            self.obj
                .bind(py)
                .call_method1("remove_all", (user_id,))
                .map(drop)
        })
        .map_err(py_store_err)
    }
}

/// The store backend the bound `IdentDb` runs over: either the built-in
/// in-memory store or a caller-supplied Python object. A single enum keeps the
/// generic `gi::IdentDb<S>` monomorphized to one type so one `#[pyclass]`
/// serves both deployment modes.
pub(crate) enum IdentBackend {
    InMemory(InMemoryIdentityStore),
    Py(PyIdentityStore),
}

macro_rules! backend_dispatch {
    ($self:ident, $s:ident => $call:expr) => {
        match $self {
            IdentBackend::InMemory($s) => $call,
            IdentBackend::Py($s) => $call,
        }
    };
}

impl IdentityStore for IdentBackend {
    fn for_user(&self, user_id: &str) -> Result<Vec<GNameId>, StoreError> {
        backend_dispatch!(self, s => s.for_user(user_id))
    }
    fn user_for(&self, value: &str) -> Result<Option<String>, StoreError> {
        backend_dispatch!(self, s => s.user_for(value))
    }
    fn find(
        &self,
        user_id: &str,
        filter: &gamlastan::idp::ident::NameIdFilter,
    ) -> Result<Vec<GNameId>, StoreError> {
        backend_dispatch!(self, s => s.find(user_id, filter))
    }
    fn find_durable(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
        format: &str,
    ) -> Result<Option<GNameId>, StoreError> {
        backend_dispatch!(self, s => s.find_durable(user_id, sp_name_qualifier, name_qualifier, format))
    }
    fn get_or_insert_durable(
        &self,
        user_id: &str,
        candidate: GNameId,
    ) -> Result<GNameId, InsertError> {
        backend_dispatch!(self, s => s.get_or_insert_durable(user_id, candidate))
    }
    fn insert(&self, user_id: &str, name_id: GNameId) -> Result<(), InsertError> {
        backend_dispatch!(self, s => s.insert(user_id, name_id))
    }
    fn replace(&self, user_id: &str, name_id: GNameId) -> Result<(), InsertError> {
        backend_dispatch!(self, s => s.replace(user_id, name_id))
    }
    fn remove(&self, value: &str) -> Result<(), StoreError> {
        backend_dispatch!(self, s => s.remove(value))
    }
    fn remove_all(&self, user_id: &str) -> Result<(), StoreError> {
        backend_dispatch!(self, s => s.remove_all(user_id))
    }
}

/// Map an `IdentError` to the Python exception hierarchy: a backend failure is
/// `SamlStoreError`, everything else `SamlIdentError`.
fn ident_error(e: IdentError) -> PyErr {
    match e {
        IdentError::Store(e) => store_err(e),
        IdentError::DurableExists => NameIdDurableExists::new_err(e.to_string()),
        IdentError::ValueTaken => NameIdValueTaken::new_err(e.to_string()),
        other => ident_err(other),
    }
}

/// The IdP identity database (pysaml2 `IdentDB`): the bidirectional mapping
/// between local user ids and the NameIDs issued to relying parties, plus
/// NameID generation honoring `NameIDPolicy` and the server side of the
/// ManageNameID / NameIDMapping profiles.
#[pyclass(module = "pygamlastan.idp", name = "IdentDb")]
pub struct IdentDb {
    pub(crate) inner: gi::IdentDb<IdentBackend>,
}

#[pymethods]
impl IdentDb {
    /// Create an identity database for `idp_entity_id` (used as the default
    /// NameQualifier). With `store=None` it is in-memory; pass an object
    /// implementing the record-shaped `IdentityStore` protocol (see `IdentityStore` in
    /// `idp.pyi`) to back it with external storage.
    /// `domain` sets the domain appended to email-format NameIDs.
    ///
    /// Transient NameIDs are not stored by default: they are one-time-use, and
    /// the default per-SP format is transient, so storing every one would add a
    /// record per response. The cost is that `find_local_id` cannot resolve a
    /// transient NameID, which a back-channel (SOAP) LogoutRequest carrying one
    /// needs. Set `persist_transient=True` to store them (the backend must then
    /// expire them: the record trait has no expiry).
    #[new]
    #[pyo3(signature = (idp_entity_id, store=None, domain=None, persist_transient=false))]
    fn new(
        idp_entity_id: String,
        store: Option<Py<PyAny>>,
        domain: Option<String>,
        persist_transient: bool,
    ) -> Self {
        let backend = match store {
            Some(obj) => IdentBackend::Py(PyIdentityStore { obj }),
            None => IdentBackend::InMemory(InMemoryIdentityStore::new()),
        };
        let mut inner = gi::IdentDb::new(backend, idp_entity_id);
        if let Some(domain) = domain {
            inner = inner.with_domain(domain);
        }
        if persist_transient {
            inner = inner.with_persist_transient(true);
        }
        IdentDb { inner }
    }

    /// Associate a NameID with a local user (maintains both directions).
    fn store(&self, user_id: &str, name_id: &NameId) -> PyResult<()> {
        self.inner
            .store(user_id, &name_id.inner)
            .map_err(ident_error)
    }
    /// The local user a NameID was issued to, if known.
    fn find_local_id(&self, name_id: &NameId) -> PyResult<Option<String>> {
        self.inner.find_local_id(&name_id.inner).map_err(store_err)
    }
    /// All NameIDs stored for a local user.
    fn name_ids_for(&self, user_id: &str) -> PyResult<Vec<NameId>> {
        self.inner
            .name_ids_for(user_id)
            .map(|v| v.into_iter().map(NameId::wrap).collect())
            .map_err(store_err)
    }
    /// An existing non-transient NameID matching (user, SP, NameQualifier).
    #[pyo3(signature = (user_id, sp_name_qualifier=None, name_qualifier=None))]
    fn match_local_id(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
    ) -> PyResult<Option<NameId>> {
        self.inner
            .match_local_id(user_id, sp_name_qualifier, name_qualifier)
            .map(|n| n.map(NameId::wrap))
            .map_err(store_err)
    }
    /// Generate a fresh transient NameID for the user.
    #[pyo3(signature = (user_id, sp_name_qualifier=None))]
    fn transient_nameid(&self, user_id: &str, sp_name_qualifier: Option<&str>) -> PyResult<NameId> {
        self.inner
            .transient_nameid(user_id, sp_name_qualifier)
            .map(NameId::wrap)
            .map_err(store_err)
    }
    /// Get-or-create a stable persistent NameID for (user, SP).
    #[pyo3(signature = (user_id, sp_name_qualifier=None))]
    fn persistent_nameid(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
    ) -> PyResult<NameId> {
        self.inner
            .persistent_nameid(user_id, sp_name_qualifier)
            .map(NameId::wrap)
            .map_err(store_err)
    }
    /// Construct a NameID honoring an incoming `NameIDPolicy`, falling back to
    /// `default_format`. Raises `SamlIdentError` if no format can be determined
    /// or AllowCreate forbids minting a persistent id.
    #[pyo3(signature = (user_id, sp_entity_id, name_id_policy=None, default_format=None))]
    fn construct_nameid(
        &self,
        user_id: &str,
        sp_entity_id: &str,
        name_id_policy: Option<&NameIdPolicy>,
        default_format: Option<&str>,
    ) -> PyResult<NameId> {
        self.inner
            .construct_nameid(
                user_id,
                sp_entity_id,
                name_id_policy.map(|p| &p.inner),
                default_format,
            )
            .map(NameId::wrap)
            .map_err(ident_error)
    }
    /// Apply a ManageNameID `NewID` (record the SP-provided identifier).
    /// Raises `SamlIdentError` if the NameID is unknown.
    fn manage_name_id_new_id(&self, name_id: &NameId, new_id: String) -> PyResult<NameId> {
        self.inner
            .handle_manage_name_id_request(&name_id.inner, &NewIdOrTerminate::NewId(new_id))
            .map(NameId::wrap)
            .map_err(ident_error)
    }
    /// Apply a ManageNameID `Terminate` (drop the association).
    /// Raises `SamlIdentError` if the NameID is unknown.
    fn manage_name_id_terminate(&self, name_id: &NameId) -> PyResult<NameId> {
        self.inner
            .handle_manage_name_id_request(&name_id.inner, &NewIdOrTerminate::Terminate)
            .map(NameId::wrap)
            .map_err(ident_error)
    }
    /// Resolve a NameIDMappingRequest: return an existing NameID matching the
    /// policy, or create one when AllowCreate permits. Raises `SamlIdentError`.
    fn handle_name_id_mapping_request(
        &self,
        name_id: &NameId,
        name_id_policy: &NameIdPolicy,
    ) -> PyResult<NameId> {
        self.inner
            .handle_name_id_mapping_request(&name_id.inner, &name_id_policy.inner)
            .map(NameId::wrap)
            .map_err(ident_error)
    }
    /// Forget a single NameID.
    fn remove_remote(&self, name_id: &NameId) -> PyResult<()> {
        self.inner.remove_remote(&name_id.inner).map_err(store_err)
    }
    /// Forget every NameID for a local user.
    fn remove_local(&self, user_id: &str) -> PyResult<()> {
        self.inner.remove_local(user_id).map_err(store_err)
    }
}

// ---------------------------------------------------------------------------
// Entity categories
// ---------------------------------------------------------------------------

/// Resolve a shipped entity-category policy by its short name.
fn shipped_policy(name: &str) -> PyResult<&'static gec::EntityCategoryPolicy> {
    match name {
        "edugain" => Ok(&gec::EDUGAIN),
        "refeds" => Ok(&gec::REFEDS),
        "incommon" => Ok(&gec::INCOMMON),
        "swamid" => Ok(&gec::SWAMID),
        "refeds-access" | "refeds_access" => Ok(&gec::REFEDS_ACCESS_RULES),
        "at_egov_pvp2" => Ok(&gec::AT_EGOV_PVP2_POLICY),
        other => Err(policy_err(format!(
            "unknown shipped entity-category policy {other:?} (known: edugain, refeds, \
             incommon, swamid, refeds-access, at_egov_pvp2)"
        ))),
    }
}

/// A single entity-category release rule (releases `attributes` when all of
/// `categories` are present on the SP and none of `conflicts` is).
#[pyclass(
    module = "pygamlastan.idp",
    name = "EntityCategoryRule",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct EntityCategoryRule {
    inner: gec::OwnedEntityCategoryRule,
}

#[pymethods]
impl EntityCategoryRule {
    #[new]
    #[pyo3(signature = (categories, attributes, conflicts=None, only_required=false))]
    fn new(
        categories: Vec<String>,
        attributes: Vec<String>,
        conflicts: Option<Vec<String>>,
        only_required: bool,
    ) -> Self {
        let mut rule = gec::OwnedEntityCategoryRule::new(categories, attributes);
        if let Some(conflicts) = conflicts {
            rule = rule.with_conflicts(conflicts);
        }
        rule = rule.with_only_required(only_required);
        EntityCategoryRule { inner: rule }
    }
    #[getter]
    fn categories(&self) -> Vec<String> {
        self.inner.categories.clone()
    }
    #[getter]
    fn attributes(&self) -> Vec<String> {
        self.inner.attributes.clone()
    }
    #[getter]
    fn conflicts(&self) -> Vec<String> {
        self.inner.conflicts.clone()
    }
    #[getter]
    fn only_required(&self) -> bool {
        self.inner.only_required
    }
}

/// A named set of entity-category release rules. Build one from custom rules,
/// optionally seeded from a shipped policy via `extend`.
#[pyclass(
    module = "pygamlastan.idp",
    name = "EntityCategoryPolicy",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct EntityCategoryPolicy {
    inner: gec::OwnedEntityCategoryPolicy,
}

#[pymethods]
impl EntityCategoryPolicy {
    #[new]
    #[pyo3(signature = (name, rules=None, extend=None))]
    fn new(
        name: String,
        rules: Option<Vec<EntityCategoryRule>>,
        extend: Option<&str>,
    ) -> PyResult<Self> {
        let mut inner = gec::OwnedEntityCategoryPolicy::new(name);
        if let Some(shipped) = extend {
            inner = inner.extend_from_static(shipped_policy(shipped)?);
        }
        for rule in rules.unwrap_or_default() {
            inner.push_rule(rule.inner);
        }
        Ok(EntityCategoryPolicy { inner })
    }
    /// The shipped policy `name` (e.g. "swamid") as an owned, extensible policy.
    #[staticmethod]
    fn shipped(name: &str) -> PyResult<Self> {
        Ok(EntityCategoryPolicy {
            inner: shipped_policy(name)?.as_owned(),
        })
    }
    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }
}

/// Compute the releasable local (lowercased) attribute names for an SP given a
/// set of entity-category policies, the SP's published categories, and the
/// lowercased local names the SP marks required (consulted by `only_required`).
#[pyfunction]
#[pyo3(signature = (policies, sp_entity_categories, required_local_names=None))]
fn releasable_attributes(
    policies: Vec<EntityCategoryPolicy>,
    sp_entity_categories: Vec<String>,
    required_local_names: Option<Vec<String>>,
) -> Vec<String> {
    let owned: Vec<gec::OwnedEntityCategoryPolicy> =
        policies.into_iter().map(|p| p.inner).collect();
    let required = required_local_names.unwrap_or_default();
    let mut out: Vec<String> =
        gec::releasable_attributes_owned(&owned, &sp_entity_categories, &required)
            .into_iter()
            .collect();
    out.sort();
    out
}

/// Parse the SP's `subject-id:req` metadata values into one of `"none"`,
/// `"subject-id"`, `"pairwise-id"`, `"any"`.
#[pyfunction]
fn subject_id_req_from_metadata(values: Vec<String>) -> &'static str {
    subject_id_req_str(gec::SubjectIdReq::from_metadata_values(&values))
}

fn subject_id_req_str(req: gec::SubjectIdReq) -> &'static str {
    match req {
        gec::SubjectIdReq::None => "none",
        gec::SubjectIdReq::SubjectId => "subject-id",
        gec::SubjectIdReq::PairwiseId => "pairwise-id",
        gec::SubjectIdReq::Any => "any",
    }
}

fn subject_id_req_from_str(s: &str) -> PyResult<gec::SubjectIdReq> {
    match s {
        "none" => Ok(gec::SubjectIdReq::None),
        "subject-id" => Ok(gec::SubjectIdReq::SubjectId),
        "pairwise-id" => Ok(gec::SubjectIdReq::PairwiseId),
        "any" => Ok(gec::SubjectIdReq::Any),
        other => Err(policy_err(format!(
            "invalid subject_id_req {other:?} (expected none, subject-id, pairwise-id, any)"
        ))),
    }
}

// ---------------------------------------------------------------------------
// SignTargets
// ---------------------------------------------------------------------------

/// Which messages the IdP signs for an SP.
#[pyclass(
    module = "pygamlastan.idp",
    name = "SignTargets",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct SignTargets {
    inner: gpol::SignTargets,
}

#[pymethods]
impl SignTargets {
    #[new]
    #[pyo3(signature = (response=false, assertion=false, on_demand=false))]
    fn new(response: bool, assertion: bool, on_demand: bool) -> Self {
        SignTargets {
            inner: gpol::SignTargets {
                response,
                assertion,
                on_demand,
            },
        }
    }
    #[getter]
    fn response(&self) -> bool {
        self.inner.response
    }
    #[getter]
    fn assertion(&self) -> bool {
        self.inner.assertion
    }
    #[getter]
    fn on_demand(&self) -> bool {
        self.inner.on_demand
    }
    /// Resolve the on-demand part against the SP's `WantAssertionsSigned` flag.
    fn resolve(&self, sp_wants_assertions_signed: bool) -> ResolvedSignTargets {
        ResolvedSignTargets {
            inner: self.inner.resolve(sp_wants_assertions_signed),
        }
    }
}

/// The concrete signing decision for one response.
#[pyclass(module = "pygamlastan.idp", name = "ResolvedSignTargets", frozen)]
pub struct ResolvedSignTargets {
    inner: gpol::ResolvedSignTargets,
}

#[pymethods]
impl ResolvedSignTargets {
    #[getter]
    fn sign_response(&self) -> bool {
        self.inner.sign_response
    }
    #[getter]
    fn sign_assertion(&self) -> bool {
        self.inner.sign_assertion
    }
}

// ---------------------------------------------------------------------------
// PolicyEntry / ReleasePolicy
// ---------------------------------------------------------------------------

/// One attribute-release policy entry (per SP, or the `"default"` fallback).
#[pyclass(
    module = "pygamlastan.idp",
    name = "PolicyEntry",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct PolicyEntry {
    inner: gpol::PolicyEntry,
}

#[pymethods]
impl PolicyEntry {
    #[new]
    #[pyo3(signature = (
        nameid_format=None,
        name_form=None,
        lifetime_seconds=None,
        sign=None,
        fail_on_missing_requested=None,
        entity_categories=None,
        owned_entity_categories=None,
        attribute_restrictions=None,
        session_lifetime_seconds=None,
        supported_nameid_formats=None,
        signing_preference=None,
        deny_unconfigured_release=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        nameid_format: Option<String>,
        name_form: Option<String>,
        lifetime_seconds: Option<i64>,
        sign: Option<SignTargets>,
        fail_on_missing_requested: Option<bool>,
        entity_categories: Option<Vec<String>>,
        owned_entity_categories: Option<Vec<EntityCategoryPolicy>>,
        attribute_restrictions: Option<Vec<(String, Option<Vec<String>>)>>,
        session_lifetime_seconds: Option<i64>,
        supported_nameid_formats: Option<Vec<String>>,
        signing_preference: Option<SigningPreference>,
        deny_unconfigured_release: Option<bool>,
    ) -> PyResult<Self> {
        let mut entry = gpol::PolicyEntry::new();
        if let Some(secs) = session_lifetime_seconds {
            if secs < 0 {
                return Err(policy_err(format!(
                    "session_lifetime_seconds must be non-negative, got {secs}"
                )));
            }
            entry = entry.with_session_lifetime(TimeDelta::seconds(secs));
        }
        if let Some(formats) = supported_nameid_formats {
            entry = entry.with_supported_nameid_formats(formats);
        }
        if let Some(p) = signing_preference {
            entry = entry.with_signing_preference(p.inner);
        }
        if let Some(deny) = deny_unconfigured_release {
            entry = entry.with_deny_unconfigured_release(deny);
        }
        if let Some(f) = nameid_format {
            entry = entry.with_nameid_format(f);
        }
        if let Some(f) = name_form {
            entry = entry.with_name_form(f);
        }
        if let Some(secs) = lifetime_seconds {
            if secs < 0 {
                return Err(policy_err(format!(
                    "lifetime_seconds must be non-negative, got {secs}: a negative \
                     assertion lifetime would mint already-expired assertions"
                )));
            }
            entry = entry.with_lifetime(TimeDelta::seconds(secs));
        }
        if let Some(s) = sign {
            entry = entry.with_sign(s.inner);
        }
        if let Some(fail) = fail_on_missing_requested {
            entry = entry.with_fail_on_missing_requested(fail);
        }
        // Shipped entity-category policies (by name) and caller-built owned ones
        // are merged into a single owned list (with_owned_entity_categories), so
        // both kinds can be combined on one entry.
        if entity_categories.is_some() || owned_entity_categories.is_some() {
            let mut owned: Vec<gec::OwnedEntityCategoryPolicy> = Vec::new();
            for name in entity_categories.unwrap_or_default() {
                owned.push(shipped_policy(&name)?.as_owned());
            }
            for p in owned_entity_categories.unwrap_or_default() {
                owned.push(p.inner);
            }
            entry = entry.with_owned_entity_categories(owned);
        }
        if let Some(restrictions) = attribute_restrictions {
            // Borrow into the &[(&str, Option<&[&str]>)] shape the builder wants.
            let borrowed: Vec<(&str, Option<Vec<&str>>)> = restrictions
                .iter()
                .map(|(name, pats)| {
                    (
                        name.as_str(),
                        pats.as_ref()
                            .map(|p| p.iter().map(String::as_str).collect()),
                    )
                })
                .collect();
            let as_slices: Vec<(&str, Option<&[&str]>)> = borrowed
                .iter()
                .map(|(name, pats)| (*name, pats.as_deref()))
                .collect();
            entry = entry
                .with_attribute_restrictions(&as_slices)
                .map_err(policy_err)?;
        }
        Ok(PolicyEntry { inner: entry })
    }
}

/// The IdP attribute-release policy (pysaml2 `Policy`). Per-knob resolution is
/// SP entry, then the SP's registration-authority entry, then `"default"`.
#[pyclass(module = "pygamlastan.idp", name = "ReleasePolicy")]
pub struct ReleasePolicy {
    pub(crate) inner: gpol::ReleasePolicy,
}

#[pymethods]
impl ReleasePolicy {
    #[new]
    #[pyo3(signature = (default=None))]
    fn new(default: Option<PolicyEntry>) -> Self {
        let inner = match default {
            Some(entry) => gpol::ReleasePolicy::with_default(entry.inner),
            None => gpol::ReleasePolicy::new(),
        };
        ReleasePolicy { inner }
    }
    /// Add or replace the entry for an SP entity id (or `"default"`).
    fn insert(&mut self, sp_entity_id: String, entry: PolicyEntry) {
        self.inner.insert(sp_entity_id, entry.inner);
    }
    /// Record an SP's registrationAuthority so resolution can fall back to a
    /// per-authority entry when the SP has no entry of its own.
    fn set_registration_authority(&mut self, sp_entity_id: String, registration_authority: String) {
        self.inner
            .set_registration_authority(sp_entity_id, registration_authority);
    }
    /// Record an SP's registration authority straight from its parsed metadata
    /// (`mdrpi:RegistrationInfo/@registrationAuthority`). No-op if absent.
    fn register_sp_metadata(&mut self, entity: &EntityDescriptor) {
        self.inner.register_sp_metadata(&entity.inner);
    }
    /// NameID format for the SP (default: transient).
    fn nameid_format(&self, sp_entity_id: &str) -> String {
        self.inner.nameid_format(sp_entity_id)
    }
    /// Attribute NameFormat for the SP (default: URI).
    fn name_form(&self, sp_entity_id: &str) -> String {
        self.inner.name_form(sp_entity_id)
    }
    /// Assertion lifetime in seconds for the SP (default: 3600).
    fn lifetime_seconds(&self, sp_entity_id: &str) -> i64 {
        self.inner.lifetime(sp_entity_id).num_seconds()
    }
    /// Assertion NotOnOrAfter for the SP given `now`.
    fn not_on_or_after(&self, sp_entity_id: &str, now: DateTime<Utc>) -> DateTime<Utc> {
        self.inner.not_on_or_after(sp_entity_id, now)
    }
    /// Signing targets for the SP (default: nothing signed).
    fn sign(&self, sp_entity_id: &str) -> SignTargets {
        SignTargets {
            inner: self.inner.sign(sp_entity_id),
        }
    }
    /// Whether a missing required attribute aborts response building (default
    /// true).
    fn fail_on_missing_requested(&self, sp_entity_id: &str) -> bool {
        self.inner.fail_on_missing_requested(sp_entity_id)
    }
    /// SSO session lifetime in seconds for the SP
    /// (``AuthnStatement/@SessionNotOnOrAfter``); falls back to the assertion
    /// lifetime when unset.
    fn session_lifetime_seconds(&self, sp_entity_id: &str) -> i64 {
        self.inner.session_lifetime(sp_entity_id).num_seconds()
    }
    /// Whether this IdP will issue a NameID of ``format`` to the SP. With no
    /// ``supported_nameid_formats`` configured every format is accepted, as in
    /// pysaml2, except ``nameid-format:encrypted`` (never issuable) and one
    /// longer than ``MAX_NAMEID_FORMAT_LEN``. The SP's own default format is
    /// always allowed.
    fn supports_nameid_format(&self, sp_entity_id: &str, format: &str) -> bool {
        self.inner.supports_nameid_format(sp_entity_id, format)
    }
    /// Whether an SP that no attribute rule covers is released nothing (default
    /// false: everything the application supplied is released).
    fn deny_unconfigured_release(&self, sp_entity_id: &str) -> bool {
        self.inner.deny_unconfigured_release(sp_entity_id)
    }
    /// The signing algorithm preference for the SP (empty by default, which
    /// leaves the signer's defaults).
    fn signing_preference(&self, sp_entity_id: &str) -> SigningPreference {
        SigningPreference {
            inner: self.inner.signing_preference(sp_entity_id),
        }
    }
    /// Filter `attributes` for release to `sp_entity_id`. `required` / `optional`
    /// are the SP's requested attributes (each a `core.Attribute`; values, when
    /// present, narrow the released values). `sp_entity_categories` are the SP's
    /// published category URIs (entity-category release takes precedence over
    /// requested/optional matching when the entry configures it).
    /// `subject_id_req` is one of `"none"`, `"subject-id"`, `"pairwise-id"`,
    /// `"any"`. Raises `SamlPolicyError` if a required attribute/value is missing
    /// and `fail_on_missing_requested` is set.
    #[pyo3(signature = (
        attributes,
        sp_entity_id,
        sp_entity_categories=None,
        required=None,
        optional=None,
        subject_id_req="none",
    ))]
    fn filter(
        &self,
        attributes: Vec<Attribute>,
        sp_entity_id: &str,
        sp_entity_categories: Option<Vec<String>>,
        required: Option<Vec<Attribute>>,
        optional: Option<Vec<Attribute>>,
        subject_id_req: &str,
    ) -> PyResult<Vec<Attribute>> {
        let attrs: Vec<_> = attributes.into_iter().map(|a| a.inner).collect();
        let required = requested_from_attrs(required.unwrap_or_default(), true);
        let optional = requested_from_attrs(optional.unwrap_or_default(), false);
        let cats = sp_entity_categories.unwrap_or_default();
        let req = subject_id_req_from_str(subject_id_req)?;
        self.inner
            .filter(attrs, sp_entity_id, &cats, &required, &optional, req)
            .map(|out| out.into_iter().map(Attribute::wrap).collect())
            .map_err(policy_err)
    }
}

/// Wrap caller-supplied attributes as `RequestedAttribute`s with a fixed
/// required flag (the binding takes plain `core.Attribute`s rather than exposing
/// the metadata `RequestedAttribute` type).
fn requested_from_attrs(attrs: Vec<Attribute>, is_required: bool) -> Vec<RequestedAttribute> {
    attrs
        .into_iter()
        .map(|a| RequestedAttribute {
            attribute: a.inner,
            is_required: Some(is_required),
        })
        .collect()
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
    m.add_class::<IdentDb>()?;
    m.add_class::<EntityCategoryRule>()?;
    m.add_class::<EntityCategoryPolicy>()?;
    m.add_class::<SignTargets>()?;
    m.add_class::<ResolvedSignTargets>()?;
    m.add_class::<PolicyEntry>()?;
    m.add_class::<ReleasePolicy>()?;
    crate::orchestrator::register(&m)?;
    crate::conformance::register(&m)?;
    m.add_function(wrap_pyfunction!(code_name_id, &m)?)?;
    m.add_function(wrap_pyfunction!(decode_name_id, &m)?)?;
    m.add(
        "ISSUABLE_NAMEID_FORMATS",
        gpol::ISSUABLE_NAMEID_FORMATS.to_vec(),
    )?;
    m.add("MAX_NAMEID_FORMAT_LEN", gpol::MAX_NAMEID_FORMAT_LEN)?;
    m.add_function(wrap_pyfunction!(releasable_attributes, &m)?)?;
    m.add_function(wrap_pyfunction!(subject_id_req_from_metadata, &m)?)?;

    // Entity-category URIs (the values published in SP metadata under
    // http://macedir.org/entity-category).
    m.add("COCO_V1", gec::COCO_V1)?;
    m.add("COCO_V2", gec::COCO_V2)?;
    m.add(
        "REFEDS_RESEARCH_AND_SCHOLARSHIP",
        gec::REFEDS_RESEARCH_AND_SCHOLARSHIP,
    )?;
    m.add(
        "INCOMMON_RESEARCH_AND_SCHOLARSHIP",
        gec::INCOMMON_RESEARCH_AND_SCHOLARSHIP,
    )?;
    m.add("MYACADEMICID_ESI", gec::MYACADEMICID_ESI)?;
    m.add("REFEDS_PERSONALIZED", gec::REFEDS_PERSONALIZED)?;
    m.add("REFEDS_PSEUDONYMOUS", gec::REFEDS_PSEUDONYMOUS)?;
    m.add("REFEDS_ANONYMOUS", gec::REFEDS_ANONYMOUS)?;
    m.add("AT_EGOV_PVP2", gec::AT_EGOV_PVP2)?;
    m.add("AT_EGOV_PVP2_CHARGE", gec::AT_EGOV_PVP2_CHARGE)?;

    // The macedir entity-category attribute name SPs publish their categories
    // under, plus the OASIS subject-id profile attribute names.
    m.add("ENTITY_CATEGORY_ATTR", "http://macedir.org/entity-category")?;
    m.add("SUBJECT_ID_ATTR", gec::SUBJECT_ID_ATTR)?;
    m.add("PAIRWISE_ID_ATTR", gec::PAIRWISE_ID_ATTR)?;
    m.add("SUBJECT_ID_REQ_ATTR", gec::SUBJECT_ID_REQ_ATTR)?;

    Ok(())
}
