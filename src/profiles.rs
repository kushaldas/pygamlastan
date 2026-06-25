//! Bindings for `gamlastan::profiles` - Web Browser SSO (SP and IdP sides):
//! build AuthnRequests, process Responses, process AuthnRequests, build
//! Responses, plus session storage.

use chrono::{DateTime, Utc};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use gamlastan::core::assertion::name_id::NameIdOrEncryptedId;
use gamlastan::core::assertion::types::Assertion as GAssertion;
use gamlastan::core::protocol::request::AuthnContextComparison;
use gamlastan::core::protocol::response::Response as GResponse;
use gamlastan::core::protocol::ResponseRef;
use gamlastan::profiles::sso::{idp as gidp, sp as gsp, web_browser as gwb};
use gamlastan::profiles::{InMemorySessionStore as GInMemorySessionStore, SessionStore};
use gamlastan::security as gs;
use gamlastan::xml::{parse_saml, uppsala};

use crate::convert::new_submodule;
use crate::core::{Attribute, AuthnRequest, NameId, Response};
use crate::crypto::SamlVerifier;
use crate::errors::{profile_err, xml_err};
use crate::metadata::EntityDescriptor;
use crate::security::{
    response_requires_persistent_id_store_inner, PyPersistentIdStore, PyReplayCache, SecurityConfig,
};

/// Parse a `<samlp:Response>` document into an owned `Response`, mirroring
/// `xml.parse_response`. Used by `process_response_verified` so the bytes that
/// are signature-verified and the bytes that are parsed are the same input.
fn parse_response_xml(xml: &str) -> PyResult<Response> {
    let doc = uppsala::parse(xml).map_err(xml_err)?;
    let r = parse_saml::<ResponseRef<'_>>(&doc).map_err(xml_err)?;
    Ok(Response::wrap(r.to_owned()))
}

fn parse_comparison(s: Option<String>) -> PyResult<Option<AuthnContextComparison>> {
    match s {
        None => Ok(None),
        Some(v) => v
            .parse::<AuthnContextComparison>()
            .map(Some)
            .map_err(|_| profile_err(format!("invalid authn_context_comparison: {v}"))),
    }
}

type ExtractedNameId = (String, Option<String>, Option<String>, Option<String>);

fn require_profile_replay_cache(
    replay_cache_present: bool,
    unsafe_no_replay_cache: bool,
) -> PyResult<()> {
    if replay_cache_present || unsafe_no_replay_cache {
        return Ok(());
    }
    Err(profile_err(
        "process_response requires replay_cache by default; pass an \
         InMemoryReplayCache or protocol implementation, or explicitly set \
         unsafe_no_replay_cache=True for legacy unsafe processing",
    ))
}

fn require_profile_persistent_id_store(
    response: &GResponse,
    config: &SecurityConfig,
    persistent_id_store_present: bool,
    unsafe_no_persistent_id_store: bool,
) -> PyResult<()> {
    if !response_requires_persistent_id_store_inner(response, &config.inner)
        || persistent_id_store_present
        || unsafe_no_persistent_id_store
    {
        return Ok(());
    }

    Err(profile_err(
        "persistent NameID uniqueness is enabled and this response contains a \
         persistent NameID, but no persistent_id_store was provided; pass a store \
         or explicitly set unsafe_no_persistent_id_store=True for legacy unsafe \
         processing",
    ))
}

fn ensure_processable_assertions(
    response: &GResponse,
    config: &gs::SecurityConfig,
) -> PyResult<()> {
    if config.require_encrypted_assertions {
        return Err(profile_err(
            "require_encrypted_assertions is enabled, but process_response does not decrypt or prove EncryptedAssertion provenance",
        ));
    }

    if response.assertions.is_empty() && !response.encrypted_assertions.is_empty() {
        return Err(profile_err(
            "response contains EncryptedAssertion elements but no decrypted plaintext Assertion",
        ));
    }

    Ok(())
}

fn extract_name_id(assertion: &GAssertion) -> PyResult<ExtractedNameId> {
    let subject = assertion
        .subject
        .as_ref()
        .ok_or_else(|| profile_err("assertion subject has no NameID"))?;

    match &subject.name_id {
        Some(NameIdOrEncryptedId::NameId(nid)) => Ok((
            nid.value.clone(),
            nid.format.clone(),
            nid.name_qualifier.clone(),
            nid.sp_name_qualifier.clone(),
        )),
        Some(NameIdOrEncryptedId::EncryptedId(_)) => Err(profile_err(
            "encrypted NameID is not supported by this profile helper",
        )),
        None => Err(profile_err("assertion subject has no NameID")),
    }
}

#[allow(clippy::too_many_arguments)]
fn process_response_with_stores(
    response: &GResponse,
    config: &SecurityConfig,
    replay_cache: Option<&dyn gs::ReplayCache>,
    persistent_id_store: Option<&dyn gs::name_id::PersistentIdStore>,
    sp_entity_id: &str,
    acs_url: &str,
    expected_request_id: Option<&str>,
    expected_idp_entity_id: &str,
    verified_signed_ids: &[&str],
    now: DateTime<Utc>,
) -> PyResult<gwb::AuthnResult> {
    if !response.base.status.is_success() {
        return Err(profile_err(
            response
                .base
                .status
                .status_message
                .clone()
                .unwrap_or_else(|| response.base.status.status_code.value.clone()),
        ));
    }

    ensure_processable_assertions(response, &config.inner)?;

    if response.assertions.is_empty() {
        return Err(profile_err("response contains no plaintext assertions"));
    }

    let mut validator = gs::AssertionValidator::new(&config.inner);
    if let Some(cache) = replay_cache {
        validator = validator.with_replay_cache(cache);
    }
    if let Some(store) = persistent_id_store {
        validator = validator.with_persistent_id_store(store);
    }

    let params = gs::ValidationParams {
        received_url: acs_url,
        expected_idp_entity_id,
        sp_entity_id,
        acs_url,
        expected_request_id,
        client_address: None,
        relay_state: None,
        response_signature_xml: None,
        response_signature_verified: if response.base.has_signature {
            if verified_signed_ids.is_empty() {
                None
            } else {
                Some(verified_signed_ids.contains(&response.base.id.as_str()))
            }
        } else {
            None
        },
        verified_signed_ids,
        current_proxy_depth: 0,
        now,
    };

    let validation_result = validator.validate_response(response, &params);
    if !validation_result.is_valid() {
        let errors: Vec<String> = validation_result
            .failures()
            .iter()
            .map(|c| {
                format!(
                    "{}: {}",
                    c.check_name,
                    c.detail.as_deref().unwrap_or("failed")
                )
            })
            .collect();
        return Err(profile_err(format!(
            "assertion validation failed: {}",
            errors.join("; ")
        )));
    }

    let assertion = response
        .assertions
        .iter()
        .find(|a| !a.authn_statements.is_empty())
        .ok_or_else(|| profile_err("response contains no AuthnStatement"))?;
    let (name_id, name_id_format, name_qualifier, sp_name_qualifier) = extract_name_id(assertion)?;
    let authn_stmt = assertion
        .authn_statements
        .first()
        .ok_or_else(|| profile_err("response contains no AuthnStatement"))?;
    let attributes: Vec<_> = response
        .assertions
        .iter()
        .flat_map(|a| gwb::extract_attributes(&a.attribute_statements))
        .collect();

    Ok(gwb::AuthnResult {
        name_id,
        name_id_format,
        name_qualifier,
        sp_name_qualifier,
        session_index: authn_stmt.session_index.clone(),
        session_not_on_or_after: authn_stmt.session_not_on_or_after,
        authn_instant: authn_stmt.authn_instant,
        authn_context_class_ref: authn_stmt.authn_context.authn_context_class_ref.clone(),
        authn_context_decl_ref: authn_stmt.authn_context.authn_context_decl_ref.clone(),
        authenticating_authorities: authn_stmt.authn_context.authenticating_authorities.clone(),
        attributes,
        idp_entity_id: assertion.issuer.value.clone(),
        assertion_id: assertion.id.clone(),
        response_id: response.base.id.clone(),
    })
}

// ---------------------------------------------------------------------------
// AuthnRequestOptions (SP)
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.profiles", name = "AuthnRequestOptions")]
pub struct AuthnRequestOptions {
    inner: gwb::AuthnRequestOptions,
}

#[pymethods]
impl AuthnRequestOptions {
    #[new]
    #[pyo3(signature = (
        sp_entity_id, acs_url=None, acs_index=None, protocol_binding=None,
        force_authn=None, is_passive=None, name_id_format=None, allow_create=true,
        sp_name_qualifier=None, authn_context_class_refs=None, authn_context_comparison=None,
        provider_name=None, destination=None, proxy_count=None, requester_ids=None,
        attribute_consuming_service_index=None, extensions=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        sp_entity_id: String,
        acs_url: Option<String>,
        acs_index: Option<u16>,
        protocol_binding: Option<String>,
        force_authn: Option<bool>,
        is_passive: Option<bool>,
        name_id_format: Option<String>,
        allow_create: bool,
        sp_name_qualifier: Option<String>,
        authn_context_class_refs: Option<Vec<String>>,
        authn_context_comparison: Option<String>,
        provider_name: Option<String>,
        destination: Option<String>,
        proxy_count: Option<u32>,
        requester_ids: Option<Vec<String>>,
        attribute_consuming_service_index: Option<u16>,
        extensions: Option<String>,
    ) -> PyResult<Self> {
        let o = gwb::AuthnRequestOptions {
            sp_entity_id,
            acs_url,
            acs_index,
            protocol_binding,
            force_authn,
            is_passive,
            name_id_format,
            allow_create,
            sp_name_qualifier,
            authn_context_class_refs: authn_context_class_refs.unwrap_or_default(),
            authn_context_comparison: parse_comparison(authn_context_comparison)?,
            provider_name,
            destination,
            proxy_count,
            requester_ids: requester_ids.unwrap_or_default(),
            attribute_consuming_service_index,
            extensions,
        };
        Ok(AuthnRequestOptions { inner: o })
    }
}

/// Build a SAML AuthnRequest (unsigned) from options.
#[pyfunction]
fn create_authn_request(options: &AuthnRequestOptions) -> PyResult<AuthnRequest> {
    let req = gsp::create_authn_request(&options.inner).map_err(profile_err)?;
    Ok(AuthnRequest::wrap(req))
}

// ---------------------------------------------------------------------------
// AuthnResult (SP)
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.profiles", name = "AuthnResult", frozen)]
pub struct AuthnResult {
    inner: gwb::AuthnResult,
}

#[pymethods]
impl AuthnResult {
    #[getter]
    fn name_id(&self) -> &str {
        &self.inner.name_id
    }
    #[getter]
    fn name_id_format(&self) -> Option<&str> {
        self.inner.name_id_format.as_deref()
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
    fn session_index(&self) -> Option<&str> {
        self.inner.session_index.as_deref()
    }
    #[getter]
    fn session_not_on_or_after(&self) -> Option<DateTime<Utc>> {
        self.inner.session_not_on_or_after
    }
    #[getter]
    fn authn_instant(&self) -> DateTime<Utc> {
        self.inner.authn_instant
    }
    #[getter]
    fn authn_context_class_ref(&self) -> Option<&str> {
        self.inner.authn_context_class_ref.as_deref()
    }
    #[getter]
    fn authenticating_authorities(&self) -> Vec<String> {
        self.inner.authenticating_authorities.clone()
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
    /// Attributes as a {name: [values]} dict (string values only) - convenient
    /// for building a SATOSA-style attribute-value-assertion.
    fn attributes_dict(&self) -> std::collections::HashMap<String, Vec<String>> {
        let mut map: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for a in &self.inner.attributes {
            let vals: Vec<String> = a
                .values
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            map.entry(a.name.clone()).or_default().extend(vals);
        }
        map
    }
    #[getter]
    fn idp_entity_id(&self) -> &str {
        &self.inner.idp_entity_id
    }
    #[getter]
    fn assertion_id(&self) -> &str {
        &self.inner.assertion_id
    }
    #[getter]
    fn response_id(&self) -> &str {
        &self.inner.response_id
    }
    fn __repr__(&self) -> String {
        format!(
            "AuthnResult(name_id={:?}, idp={:?})",
            self.inner.name_id, self.inner.idp_entity_id
        )
    }
}

/// Validate and extract identity from a SAML Response (SP side). Pass
/// `verified_signed_ids` (from a trusted SamlVerifier) to enforce signed
/// assertions. `replay_cache` is optional (InMemoryReplayCache or a protocol).
///
/// SECURITY: `verified_signed_ids` MUST be the IDs a real `crypto.SamlVerifier`
/// returned for THIS exact response - never hand-built. If you can hand the raw
/// XML in, prefer `process_response_verified`, which verifies internally and
/// removes this footgun. `now` is for test determinism only; do not pass it in
/// production.
#[pyfunction]
#[pyo3(signature = (
    response, config, sp_entity_id, acs_url, expected_idp_entity_id,
    expected_request_id=None, verified_signed_ids=None, now=None, replay_cache=None,
    persistent_id_store=None, unsafe_no_replay_cache=false,
    unsafe_no_persistent_id_store=false,
))]
#[allow(clippy::too_many_arguments)]
fn process_response(
    response: &Response,
    config: &SecurityConfig,
    sp_entity_id: &str,
    acs_url: &str,
    expected_idp_entity_id: &str,
    expected_request_id: Option<String>,
    verified_signed_ids: Option<Vec<String>>,
    now: Option<DateTime<Utc>>,
    replay_cache: Option<Py<PyAny>>,
    persistent_id_store: Option<Py<PyAny>>,
    unsafe_no_replay_cache: bool,
    unsafe_no_persistent_id_store: bool,
) -> PyResult<AuthnResult> {
    require_profile_replay_cache(replay_cache.is_some(), unsafe_no_replay_cache)?;
    require_profile_persistent_id_store(
        &response.inner,
        config,
        persistent_id_store.is_some(),
        unsafe_no_persistent_id_store,
    )?;

    // Hold the owned Vec<String> alive, then borrow &[&str] from it (the
    // gamlastan API takes borrowed ids). `verified_signed_ids` should be exactly
    // the ids a trusted SamlVerifier returned for THIS response - that is how
    // signed-assertion enforcement is bound to real crypto, not just to the
    // presence of a <Signature> element.
    let signed_ids = verified_signed_ids.unwrap_or_default();
    let signed_id_refs: Vec<&str> = signed_ids.iter().map(|s| s.as_str()).collect();
    let now = now.unwrap_or_else(Utc::now);
    // Adapt the optional Python replay cache to `&dyn ReplayCache`. `py_cache`
    // is a separate binding so the trait object borrows something that outlives
    // the call below; the explicit cast turns `&PyReplayCache` into `&dyn`.
    let py_cache = replay_cache.map(|obj| PyReplayCache { obj });
    let cache_ref: Option<&dyn gamlastan::security::ReplayCache> = py_cache
        .as_ref()
        .map(|c| c as &dyn gamlastan::security::ReplayCache);
    let py_pid = persistent_id_store.map(|obj| PyPersistentIdStore { obj });
    let pid_ref: Option<&dyn gs::name_id::PersistentIdStore> = py_pid
        .as_ref()
        .map(|s| s as &dyn gs::name_id::PersistentIdStore);

    let result = process_response_with_stores(
        &response.inner,
        config,
        cache_ref,
        pid_ref,
        sp_entity_id,
        acs_url,
        expected_request_id.as_deref(),
        expected_idp_entity_id,
        &signed_id_refs,
        now,
    )?;
    Ok(AuthnResult { inner: result })
}

/// Safe, opinionated SP entry point: verify the response signature internally,
/// then validate and extract identity.
///
/// Unlike `process_response`, this performs XML-DSig verification with the given
/// `verifier` over the EXACT `response_xml` bytes and feeds only the
/// cryptographically verified reference IDs into validation. The caller cannot
/// assert "this was signed" without real crypto, which closes the
/// auth-bypass-by-mis-integration gap. Raises `SamlCryptoError` if the signature
/// is missing or invalid.
///
/// Prefer this over the lower-level `process_response` +
/// `verified_signed_ids=...` wiring unless you have a specific reason to do
/// verification yourself. SECURITY: `now` is for test determinism only - do not
/// pass it in production (it defaults to the system clock).
#[pyfunction]
#[pyo3(signature = (
    response_xml, verifier, config, sp_entity_id, acs_url, expected_idp_entity_id,
    expected_request_id=None, now=None, replay_cache=None, persistent_id_store=None,
    unsafe_no_replay_cache=false, unsafe_no_persistent_id_store=false,
))]
#[allow(clippy::too_many_arguments)]
fn process_response_verified(
    response_xml: &str,
    verifier: &SamlVerifier,
    config: &SecurityConfig,
    sp_entity_id: &str,
    acs_url: &str,
    expected_idp_entity_id: &str,
    expected_request_id: Option<String>,
    now: Option<DateTime<Utc>>,
    replay_cache: Option<Py<PyAny>>,
    persistent_id_store: Option<Py<PyAny>>,
    unsafe_no_replay_cache: bool,
    unsafe_no_persistent_id_store: bool,
) -> PyResult<AuthnResult> {
    require_profile_replay_cache(replay_cache.is_some(), unsafe_no_replay_cache)?;

    // 1. Verify the signature over the exact bytes; this is the only source of
    //    truth for which IDs count as signed (errors if invalid/unsigned).
    let signed_ids = verifier.verified_signed_ids(response_xml)?;
    let signed_id_refs: Vec<&str> = signed_ids.iter().map(|s| s.as_str()).collect();
    // 2. Parse the SAME bytes into a Response, then validate.
    let parsed = parse_response_xml(response_xml)?;
    require_profile_persistent_id_store(
        &parsed.inner,
        config,
        persistent_id_store.is_some(),
        unsafe_no_persistent_id_store,
    )?;
    let now = now.unwrap_or_else(Utc::now);
    let py_cache = replay_cache.map(|obj| PyReplayCache { obj });
    let cache_ref: Option<&dyn gamlastan::security::ReplayCache> = py_cache
        .as_ref()
        .map(|c| c as &dyn gamlastan::security::ReplayCache);
    let py_pid = persistent_id_store.map(|obj| PyPersistentIdStore { obj });
    let pid_ref: Option<&dyn gs::name_id::PersistentIdStore> = py_pid
        .as_ref()
        .map(|s| s as &dyn gs::name_id::PersistentIdStore);

    let result = process_response_with_stores(
        &parsed.inner,
        config,
        cache_ref,
        pid_ref,
        sp_entity_id,
        acs_url,
        expected_request_id.as_deref(),
        expected_idp_entity_id,
        &signed_id_refs,
        now,
    )?;
    Ok(AuthnResult { inner: result })
}

// ---------------------------------------------------------------------------
// ProcessedAuthnRequest (IdP)
// ---------------------------------------------------------------------------

#[pyclass(
    module = "pygamlastan.profiles",
    name = "ProcessedAuthnRequest",
    frozen
)]
pub struct ProcessedAuthnRequest {
    inner: gidp::ProcessedAuthnRequest,
}

#[pymethods]
impl ProcessedAuthnRequest {
    #[getter]
    fn request_id(&self) -> &str {
        &self.inner.request_id
    }
    #[getter]
    fn sp_entity_id(&self) -> &str {
        &self.inner.sp_entity_id
    }
    #[getter]
    fn acs_url(&self) -> &str {
        &self.inner.acs_url
    }
    #[getter]
    fn acs_binding(&self) -> &str {
        &self.inner.acs_binding
    }
    #[getter]
    fn force_authn(&self) -> bool {
        self.inner.force_authn
    }
    #[getter]
    fn is_passive(&self) -> bool {
        self.inner.is_passive
    }
    #[getter]
    fn requested_name_id_format(&self) -> Option<&str> {
        self.inner.requested_name_id_format.as_deref()
    }
    #[getter]
    fn allow_create(&self) -> bool {
        self.inner.allow_create
    }
    #[getter]
    fn requested_authn_context_class_refs(&self) -> Vec<String> {
        self.inner.requested_authn_context_class_refs.clone()
    }
    #[getter]
    fn attribute_consuming_service_index(&self) -> Option<u16> {
        self.inner.attribute_consuming_service_index
    }
}

/// Process an incoming AuthnRequest (IdP side), requiring SP metadata by default.
#[pyfunction]
#[pyo3(signature = (request, sp_metadata=None, unsafe_allow_missing_metadata=false))]
fn process_authn_request(
    request: &AuthnRequest,
    sp_metadata: Option<&EntityDescriptor>,
    unsafe_allow_missing_metadata: bool,
) -> PyResult<ProcessedAuthnRequest> {
    if sp_metadata.is_none() && !unsafe_allow_missing_metadata {
        return Err(profile_err(
            "process_authn_request requires SP metadata by default; pass \
             sp_metadata or explicitly set unsafe_allow_missing_metadata=True \
             for legacy unsafe processing",
        ));
    }

    let sp_desc = sp_metadata.and_then(|m| m.inner.sp_sso_descriptors().first());
    if sp_metadata.is_some() && sp_desc.is_none() && !unsafe_allow_missing_metadata {
        return Err(profile_err(
            "SP metadata does not contain an SPSSODescriptor",
        ));
    }
    let processed = gidp::process_authn_request(&request.inner, sp_desc).map_err(profile_err)?;
    Ok(ProcessedAuthnRequest { inner: processed })
}

// ---------------------------------------------------------------------------
// ResponseOptions + create_response (IdP)
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.profiles", name = "ResponseOptions")]
pub struct ResponseOptions {
    inner: gwb::ResponseOptions,
}

#[pymethods]
impl ResponseOptions {
    #[new]
    #[pyo3(signature = (
        idp_entity_id, sp_entity_id, acs_url, assertion_lifetime_seconds=300,
        in_response_to=None, session_index=None, session_not_on_or_after=None,
        authn_context_class_ref=None, client_address=None, attributes=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        idp_entity_id: String,
        sp_entity_id: String,
        acs_url: String,
        assertion_lifetime_seconds: u64,
        in_response_to: Option<String>,
        session_index: Option<String>,
        session_not_on_or_after: Option<DateTime<Utc>>,
        authn_context_class_ref: Option<String>,
        client_address: Option<String>,
        attributes: Option<Vec<Attribute>>,
    ) -> Self {
        let attributes = attributes
            .unwrap_or_default()
            .into_iter()
            .map(|a| a.inner)
            .collect();
        ResponseOptions {
            inner: gwb::ResponseOptions {
                idp_entity_id,
                in_response_to,
                sp_entity_id,
                acs_url,
                assertion_lifetime_seconds,
                session_index,
                session_not_on_or_after,
                authn_context_class_ref,
                client_address,
                attributes,
            },
        }
    }
}

/// Build a signed-or-unsigned SAML Response carrying an assertion (IdP side).
#[pyfunction]
#[pyo3(signature = (options, principal_name_id, now=None))]
fn create_response(
    options: &ResponseOptions,
    principal_name_id: &NameId,
    now: Option<DateTime<Utc>>,
) -> Response {
    let now = now.unwrap_or_else(Utc::now);
    let resp = gidp::create_response(&options.inner, &principal_name_id.inner, now);
    Response::wrap(resp)
}

/// Build an unsolicited (IdP-initiated) Response.
#[pyfunction]
#[pyo3(signature = (
    idp_entity_id, sp_entity_id, acs_url, principal_name_id, attributes=None,
    authn_context_class_ref=None, assertion_lifetime_seconds=300, session_index=None,
    session_not_on_or_after=None, client_address=None, now=None,
))]
#[allow(clippy::too_many_arguments)]
fn create_unsolicited_response(
    idp_entity_id: &str,
    sp_entity_id: &str,
    acs_url: &str,
    principal_name_id: &NameId,
    attributes: Option<Vec<Attribute>>,
    authn_context_class_ref: Option<String>,
    assertion_lifetime_seconds: u64,
    session_index: Option<String>,
    session_not_on_or_after: Option<DateTime<Utc>>,
    client_address: Option<String>,
    now: Option<DateTime<Utc>>,
) -> Response {
    let now = now.unwrap_or_else(Utc::now);
    let attrs: Vec<_> = attributes
        .unwrap_or_default()
        .into_iter()
        .map(|a| a.inner)
        .collect();
    let resp = gidp::create_unsolicited_response(
        idp_entity_id,
        sp_entity_id,
        acs_url,
        &principal_name_id.inner,
        &attrs,
        authn_context_class_ref.as_deref(),
        assertion_lifetime_seconds,
        session_index.as_deref(),
        session_not_on_or_after,
        client_address.as_deref(),
        now,
    );
    Response::wrap(resp)
}

// ---------------------------------------------------------------------------
// Session store (built-in)
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.profiles", name = "InMemorySessionStore")]
pub struct InMemorySessionStore {
    inner: GInMemorySessionStore,
}

#[pymethods]
impl InMemorySessionStore {
    #[new]
    fn new() -> Self {
        InMemorySessionStore {
            inner: GInMemorySessionStore::new(),
        }
    }
    fn __len__(&self) -> usize {
        self.inner.len()
    }
    fn destroy_session(&self, session_index: &str) -> bool {
        self.inner.destroy_session(session_index)
    }
    fn cleanup_expired(&self) {
        self.inner.cleanup_expired();
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "profiles")?;
    m.add_class::<AuthnRequestOptions>()?;
    m.add_class::<AuthnResult>()?;
    m.add_class::<ProcessedAuthnRequest>()?;
    m.add_class::<ResponseOptions>()?;
    m.add_class::<InMemorySessionStore>()?;
    m.add_function(wrap_pyfunction!(create_authn_request, &m)?)?;
    m.add_function(wrap_pyfunction!(process_response, &m)?)?;
    m.add_function(wrap_pyfunction!(process_response_verified, &m)?)?;
    m.add_function(wrap_pyfunction!(process_authn_request, &m)?)?;
    m.add_function(wrap_pyfunction!(create_response, &m)?)?;
    m.add_function(wrap_pyfunction!(create_unsolicited_response, &m)?)?;
    Ok(())
}
