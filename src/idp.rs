//! Bindings for `gamlastan::idp` - IdP-side infrastructure: eduPersonTargetedID
//! generation, the authentication broker, NameID storage coding, and an
//! issued-assertion store.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use chrono::{DateTime, TimeDelta, Utc};

use gamlastan::core::protocol::name_id_mgmt::NewIdOrTerminate;
use gamlastan::idp as gi;
use gamlastan::idp::entity_category as gec;
use gamlastan::idp::ident::{IdentityStore, InMemoryIdentityStore};
use gamlastan::idp::policy as gpol;
use gamlastan::metadata::types::sp::RequestedAttribute;

use crate::convert::new_submodule;
use crate::core::{Assertion, Attribute, NameId, NameIdPolicy, RequestedAuthnContext};
use crate::errors::{ident_err, policy_err};
use crate::metadata::EntityDescriptor;

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
        Eptid {
            inner: gi::Eptid::new(secret),
        }
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
        AuthnBroker {
            inner: gi::AuthnBroker::new(),
        }
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
    inner: gi::InMemoryAssertionStore,
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
        self.inner
            .assertions_for_subject(name_id_value)
            .into_iter()
            .map(Assertion::wrap)
            .collect()
    }
    fn remove_assertion(&self, assertion_id: &str) {
        use gi::AssertionStore;
        self.inner.remove_assertion(assertion_id);
    }
}

// ---------------------------------------------------------------------------
// IdentDb (NameID database, pysaml2 IdentDB)
// ---------------------------------------------------------------------------

/// Adapter implementing the Rust `IdentityStore` trait by calling into a Python
/// object that provides `get(key) -> str | None`, `set(key, value)`, and
/// `remove(key)`. Lets a deployment back the NameID database with Redis/SQL/etc.
struct PyIdentityStore {
    obj: Py<PyAny>,
}

impl IdentityStore for PyIdentityStore {
    // The `IdentityStore` trait is infallible (no `Result`), so a broken Python
    // backend cannot raise here. Swallowing the error silently would make a
    // backend outage look like a cache miss (e.g. minting a fresh persistent
    // NameID instead of returning the stored one), so every failure is reported
    // via `write_unraisable` before falling back to the "missing" answer.
    fn get(&self, key: &str) -> Option<String> {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            match obj
                .call_method1("get", (key,))
                .and_then(|r| r.extract::<Option<String>>())
            {
                Ok(v) => v,
                Err(e) => {
                    e.write_unraisable(py, Some(obj));
                    None
                }
            }
        })
    }
    fn set(&self, key: &str, value: String) {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            if let Err(e) = obj.call_method1("set", (key, value)) {
                e.write_unraisable(py, Some(obj));
            }
        });
    }
    fn remove(&self, key: &str) {
        Python::attach(|py| {
            let obj = self.obj.bind(py);
            if let Err(e) = obj.call_method1("remove", (key,)) {
                e.write_unraisable(py, Some(obj));
            }
        });
    }
}

/// The store backend the bound `IdentDb` runs over: either the built-in
/// in-memory map or a caller-supplied Python object. A single enum keeps the
/// generic `gi::IdentDb<S>` monomorphized to one type so one `#[pyclass]`
/// serves both deployment modes.
enum IdentBackend {
    InMemory(InMemoryIdentityStore),
    Py(PyIdentityStore),
}

impl IdentityStore for IdentBackend {
    fn get(&self, key: &str) -> Option<String> {
        match self {
            IdentBackend::InMemory(s) => s.get(key),
            IdentBackend::Py(s) => s.get(key),
        }
    }
    fn set(&self, key: &str, value: String) {
        match self {
            IdentBackend::InMemory(s) => s.set(key, value),
            IdentBackend::Py(s) => s.set(key, value),
        }
    }
    fn remove(&self, key: &str) {
        match self {
            IdentBackend::InMemory(s) => s.remove(key),
            IdentBackend::Py(s) => s.remove(key),
        }
    }
}

/// The IdP identity database (pysaml2 `IdentDB`): the bidirectional mapping
/// between local user ids and the NameIDs issued to relying parties, plus
/// NameID generation honoring `NameIDPolicy` and the server side of the
/// ManageNameID / NameIDMapping profiles.
#[pyclass(module = "pygamlastan.idp", name = "IdentDb")]
pub struct IdentDb {
    inner: gi::IdentDb<IdentBackend>,
}

#[pymethods]
impl IdentDb {
    /// Create an identity database for `idp_entity_id` (used as the default
    /// NameQualifier). With `store=None` it is in-memory; pass an object
    /// implementing `get`/`set`/`remove` to back it with external storage.
    /// `domain` sets the domain appended to email-format NameIDs.
    #[new]
    #[pyo3(signature = (idp_entity_id, store=None, domain=None))]
    fn new(idp_entity_id: String, store: Option<Py<PyAny>>, domain: Option<String>) -> Self {
        let backend = match store {
            Some(obj) => IdentBackend::Py(PyIdentityStore { obj }),
            None => IdentBackend::InMemory(InMemoryIdentityStore::new()),
        };
        let mut inner = gi::IdentDb::new(backend, idp_entity_id);
        if let Some(domain) = domain {
            inner = inner.with_domain(domain);
        }
        IdentDb { inner }
    }

    /// Associate a NameID with a local user (maintains both directions).
    fn store(&self, user_id: &str, name_id: &NameId) {
        self.inner.store(user_id, &name_id.inner);
    }
    /// The local user a NameID was issued to, if known.
    fn find_local_id(&self, name_id: &NameId) -> Option<String> {
        self.inner.find_local_id(&name_id.inner)
    }
    /// All NameIDs stored for a local user.
    fn name_ids_for(&self, user_id: &str) -> Vec<NameId> {
        self.inner
            .name_ids_for(user_id)
            .into_iter()
            .map(NameId::wrap)
            .collect()
    }
    /// An existing non-transient NameID matching (user, SP, NameQualifier).
    #[pyo3(signature = (user_id, sp_name_qualifier=None, name_qualifier=None))]
    fn match_local_id(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
    ) -> Option<NameId> {
        self.inner
            .match_local_id(user_id, sp_name_qualifier, name_qualifier)
            .map(NameId::wrap)
    }
    /// Generate a fresh transient NameID for the user.
    #[pyo3(signature = (user_id, sp_name_qualifier=None))]
    fn transient_nameid(&self, user_id: &str, sp_name_qualifier: Option<&str>) -> NameId {
        NameId::wrap(self.inner.transient_nameid(user_id, sp_name_qualifier))
    }
    /// Get-or-create a stable persistent NameID for (user, SP).
    #[pyo3(signature = (user_id, sp_name_qualifier=None))]
    fn persistent_nameid(&self, user_id: &str, sp_name_qualifier: Option<&str>) -> NameId {
        NameId::wrap(self.inner.persistent_nameid(user_id, sp_name_qualifier))
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
            .map_err(ident_err)
    }
    /// Apply a ManageNameID `NewID` (record the SP-provided identifier).
    /// Raises `SamlIdentError` if the NameID is unknown.
    fn manage_name_id_new_id(&self, name_id: &NameId, new_id: String) -> PyResult<NameId> {
        self.inner
            .handle_manage_name_id_request(&name_id.inner, &NewIdOrTerminate::NewId(new_id))
            .map(NameId::wrap)
            .map_err(ident_err)
    }
    /// Apply a ManageNameID `Terminate` (drop the association).
    /// Raises `SamlIdentError` if the NameID is unknown.
    fn manage_name_id_terminate(&self, name_id: &NameId) -> PyResult<NameId> {
        self.inner
            .handle_manage_name_id_request(&name_id.inner, &NewIdOrTerminate::Terminate)
            .map(NameId::wrap)
            .map_err(ident_err)
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
            .map_err(ident_err)
    }
    /// Forget a single NameID.
    fn remove_remote(&self, name_id: &NameId) {
        self.inner.remove_remote(&name_id.inner);
    }
    /// Forget every NameID for a local user.
    fn remove_local(&self, user_id: &str) {
        self.inner.remove_local(user_id);
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
    ) -> PyResult<Self> {
        let mut entry = gpol::PolicyEntry::new();
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
    inner: gpol::ReleasePolicy,
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
    m.add_function(wrap_pyfunction!(code_name_id, &m)?)?;
    m.add_function(wrap_pyfunction!(decode_name_id, &m)?)?;
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
