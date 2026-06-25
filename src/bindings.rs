//! Bindings for `gamlastan::bindings` - HTTP-Redirect / HTTP-POST / Artifact
//! encode & decode as plain data functions over Python values and bytes.
//!
//! gamlastan's decode functions are generic over an `HttpRequest` trait used to
//! wire framework request objects. Python web frameworks each have their own
//! request type, so we provide a tiny `PyHttpRequest` adapter built from plain
//! query strings / duplicate-preserving form parameters and expose
//! `*_decode(params)` functions.

use std::collections::{HashMap, HashSet};

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PyIterator, PyModule};

use gamlastan::bindings as gb;
use gb::HttpRequest;

use crate::convert::new_submodule;
use crate::crypto::SamlSigner;
use crate::errors::binding_err;

/// Adapter implementing gamlastan's `HttpRequest` from plain Python data.
struct PyHttpRequest {
    method: String,
    url: String,
    query: HashMap<String, String>,
    form: HashMap<String, String>,
    body: Vec<u8>,
}

impl PyHttpRequest {
    fn get(method: &str, url: String, query: HashMap<String, String>) -> Self {
        PyHttpRequest {
            method: method.to_string(),
            url,
            query,
            form: HashMap::new(),
            body: Vec::new(),
        }
    }
    fn post(url: String, form: HashMap<String, String>, body: Vec<u8>) -> Self {
        PyHttpRequest {
            method: "POST".to_string(),
            url,
            query: HashMap::new(),
            form,
            body,
        }
    }
}

impl HttpRequest for PyHttpRequest {
    fn method(&self) -> &str {
        &self.method
    }
    fn url(&self) -> &str {
        &self.url
    }
    fn query_param(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(|s| s.as_str())
    }
    fn form_param(&self, name: &str) -> Option<&str> {
        self.form.get(name).map(|s| s.as_str())
    }
    // Headers and remote address are not needed to decode Redirect/POST/Artifact
    // messages (only query/form params and the URL are), so the data-function
    // API does not collect them. SOAP/PAOS flows that need headers are out of
    // scope for this plain-data binding.
    fn header(&self, _name: &str) -> Option<&str> {
        None
    }
    fn body(&self) -> &[u8] {
        &self.body
    }
    fn remote_addr(&self) -> Option<&str> {
        None
    }
}

fn reject_weak_binding_signature_algorithm(
    algorithm_uri: &str,
    unsafe_allow_weak_sha1: bool,
) -> PyResult<()> {
    let normalized = algorithm_uri.to_ascii_lowercase();
    if unsafe_allow_weak_sha1 || (!normalized.contains("sha1") && !normalized.contains("sha-1")) {
        return Ok(());
    }

    Err(binding_err(
        "SHA-1 signature algorithms are rejected by default; set \
         unsafe_allow_weak_sha1=True only for legacy interoperability",
    ))
}

// ---------------------------------------------------------------------------
// Decoded result types
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.bindings", name = "RedirectDecoded", frozen)]
pub struct RedirectDecoded {
    inner: gb::RedirectDecoded,
}

#[pymethods]
impl RedirectDecoded {
    #[getter]
    fn saml_xml<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.saml_xml)
    }
    /// The SAML message decoded as text. LOSSY: invalid UTF-8 is replaced with
    /// U+FFFD, so this may differ from the signed bytes. Use it for
    /// display/logging only; base any security decision on `saml_xml` (bytes).
    #[getter]
    fn saml_text(&self) -> String {
        String::from_utf8_lossy(&self.inner.saml_xml).into_owned()
    }
    #[getter]
    fn is_request(&self) -> bool {
        self.inner.is_request
    }
    #[getter]
    fn relay_state(&self) -> Option<&str> {
        self.inner.relay_state.as_deref()
    }
    #[getter]
    fn sig_alg(&self) -> Option<&str> {
        self.inner.sig_alg.as_deref()
    }
    #[getter]
    fn signature<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.inner.signature.as_ref().map(|s| PyBytes::new(py, s))
    }
    #[getter]
    fn signature_input(&self) -> Option<&str> {
        self.inner.signature_input.as_deref()
    }
}

#[pyclass(module = "pygamlastan.bindings", name = "PostDecoded", frozen)]
pub struct PostDecoded {
    inner: gb::post::PostDecoded,
}

#[pymethods]
impl PostDecoded {
    #[getter]
    fn saml_xml<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.saml_xml)
    }
    /// The SAML message decoded as text. LOSSY: invalid UTF-8 is replaced with
    /// U+FFFD, so this may differ from the signed bytes. Use it for
    /// display/logging only; base any security decision on `saml_xml` (bytes).
    #[getter]
    fn saml_text(&self) -> String {
        String::from_utf8_lossy(&self.inner.saml_xml).into_owned()
    }
    #[getter]
    fn is_request(&self) -> bool {
        self.inner.is_request
    }
    #[getter]
    fn relay_state(&self) -> Option<&str> {
        self.inner.relay_state.as_deref()
    }
}

// ---------------------------------------------------------------------------
// Redirect binding
// ---------------------------------------------------------------------------

/// Build a HTTP-Redirect URL (optionally signed) carrying a SAML message.
#[pyfunction]
#[pyo3(signature = (
    saml_xml, is_request, destination, relay_state=None, signer=None, sig_alg=None,
    unsafe_allow_weak_sha1=false,
))]
fn redirect_encode(
    saml_xml: &[u8],
    is_request: bool,
    destination: &str,
    relay_state: Option<&str>,
    signer: Option<&SamlSigner>,
    sig_alg: Option<&str>,
    unsafe_allow_weak_sha1: bool,
) -> PyResult<String> {
    let rs = match relay_state {
        Some(v) => Some(gb::RelayState::new(v).map_err(binding_err)?),
        None => None,
    };
    let signer_pair = match (signer, sig_alg) {
        (Some(s), Some(a)) => {
            reject_weak_binding_signature_algorithm(a, unsafe_allow_weak_sha1)?;
            Some((&s.inner, a))
        }
        (Some(_), None) => {
            return Err(binding_err("signer provided without sig_alg"));
        }
        _ => None,
    };
    let params = gb::RedirectEncodeParams {
        saml_xml,
        is_request,
        destination,
        relay_state: rs.as_ref(),
        signer: signer_pair,
    };
    gb::redirect_encode(&params).map_err(binding_err)
}

/// Decode a HTTP-Redirect request from its **raw** (still URL-encoded) query
/// string, e.g. `"SAMLResponse=fZ...&RelayState=abc&SigAlg=...&Signature=..."`.
///
/// Pass the query string exactly as received on the wire - do NOT URL-decode it
/// first (gamlastan decodes internally and the detached signature is computed
/// over the raw encoded parameters). `base_url` is the request URL without the
/// query, used only for signature-input reconstruction.
#[pyfunction]
#[pyo3(signature = (query, base_url=""))]
fn redirect_decode(query: &str, base_url: &str) -> PyResult<RedirectDecoded> {
    // Parse the raw query string WITHOUT decoding, preserving %xx and '+'.
    //
    // Reject duplicate occurrences of the signature-relevant parameters. A bare
    // last-wins HashMap would silently drop earlier copies, opening an HTTP
    // Parameter Pollution / signature-wrapping seam: a downstream layer (proxy,
    // framework multidict, or the verifier re-parsing the raw query) could pick
    // a different occurrence than the one decoded here. Fail closed instead.
    const SIG_PARAMS: [&str; 5] = [
        "SAMLRequest",
        "SAMLResponse",
        "SigAlg",
        "Signature",
        "RelayState",
    ];
    let mut params: HashMap<String, String> = HashMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (pair.to_string(), String::new()),
        };
        if params.contains_key(&k) && SIG_PARAMS.contains(&k.as_str()) {
            return Err(binding_err(format!("duplicate query parameter: {k}")));
        }
        params.insert(k, v);
    }
    let url = format!("{base_url}?{query}");
    let req = PyHttpRequest::get("GET", url, params);
    let inner = gb::redirect_decode(&req).map_err(binding_err)?;
    Ok(RedirectDecoded { inner })
}

// ---------------------------------------------------------------------------
// POST binding
// ---------------------------------------------------------------------------

/// Build a self-submitting HTML form for the HTTP-POST binding.
#[pyfunction]
#[pyo3(signature = (saml_xml, is_request, destination, relay_state=None))]
fn post_encode(
    saml_xml: &[u8],
    is_request: bool,
    destination: &str,
    relay_state: Option<&str>,
) -> PyResult<String> {
    let rs = match relay_state {
        Some(v) => Some(gb::RelayState::new(v).map_err(binding_err)?),
        None => None,
    };
    Ok(gb::post::post_encode(
        saml_xml,
        is_request,
        destination,
        rs.as_ref(),
    ))
}

fn post_form_from_python(
    form_params: &Bound<'_, PyAny>,
    unsafe_allow_collapsed_form: bool,
) -> PyResult<HashMap<String, String>> {
    let collapsed_form_error = || {
        binding_err(
            "post_decode requires duplicate-preserving form input by default; \
             pass a sequence of (name, value) pairs, or explicitly set \
             unsafe_allow_collapsed_form=True for legacy mapping input",
        )
    };

    if let Ok(dict) = form_params.cast::<PyDict>() {
        if !unsafe_allow_collapsed_form {
            return Err(collapsed_form_error());
        }

        let mut form = HashMap::new();
        for (key, value) in dict.iter() {
            form.insert(key.extract::<String>()?, value.extract::<String>()?);
        }
        return Ok(form);
    }

    if form_params.hasattr("items")? {
        if !unsafe_allow_collapsed_form {
            return Err(collapsed_form_error());
        }

        let items = form_params.call_method0("items").map_err(binding_err)?;
        let mut form = HashMap::new();
        for item in PyIterator::from_object(&items).map_err(binding_err)? {
            let (key, value) = item
                .and_then(|item| item.extract::<(String, String)>())
                .map_err(binding_err)?;
            form.insert(key, value);
        }
        return Ok(form);
    }

    let pairs = form_params
        .extract::<Vec<(String, String)>>()
        .map_err(|_| {
            binding_err("form_params must be a mapping or sequence of (name, value) pairs")
        })?;

    const SAML_PARAMS: [&str; 5] = [
        "SAMLRequest",
        "SAMLResponse",
        "SigAlg",
        "Signature",
        "RelayState",
    ];
    let mut seen = HashSet::new();
    let mut form = HashMap::new();
    for (key, value) in pairs {
        if !seen.insert(key.clone()) && SAML_PARAMS.contains(&key.as_str()) {
            return Err(binding_err(format!("duplicate form parameter: {key}")));
        }
        form.insert(key, value);
    }
    Ok(form)
}

/// Decode a HTTP-POST request from duplicate-preserving form parameters.
#[pyfunction]
#[pyo3(signature = (form_params, url="", unsafe_allow_collapsed_form=false))]
fn post_decode(
    form_params: &Bound<'_, PyAny>,
    url: &str,
    unsafe_allow_collapsed_form: bool,
) -> PyResult<PostDecoded> {
    let form = post_form_from_python(form_params, unsafe_allow_collapsed_form)?;
    let req = PyHttpRequest::post(url.to_string(), form, Vec::new());
    let inner = gb::post::post_decode(&req).map_err(binding_err)?;
    Ok(PostDecoded { inner })
}

/// Validate that a RelayState value is within size limits and safe.
#[pyfunction]
fn validate_relay_state(value: &str) -> PyResult<()> {
    gb::relay_state::validate_relay_state(value).map_err(binding_err)
}

// ---------------------------------------------------------------------------
// Artifact
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.bindings", name = "SamlArtifact", frozen)]
pub struct SamlArtifact {
    inner: gb::SamlArtifact,
}

#[pymethods]
impl SamlArtifact {
    /// Create a type-0x0004 artifact for `entity_id` with a 20-byte handle.
    ///
    /// SECURITY: `random_handle` is the unguessable lookup token for the resolved
    /// assertion - if supplied manually it MUST come from a CSPRNG (e.g.
    /// `secrets.token_bytes(20)`). Prefer `SamlArtifact.generate(...)`, which
    /// fills the handle for you.
    #[new]
    fn new(endpoint_index: u16, entity_id: &str, random_handle: [u8; 20]) -> Self {
        SamlArtifact {
            inner: gb::SamlArtifact::new(endpoint_index, entity_id, random_handle),
        }
    }

    /// Create a type-0x0004 artifact with a cryptographically random 20-byte
    /// handle sourced from Python's `secrets.token_bytes`. This is the safe
    /// default constructor; use it instead of passing a handle by hand.
    #[staticmethod]
    fn generate(py: Python<'_>, endpoint_index: u16, entity_id: &str) -> PyResult<Self> {
        let bytes: Vec<u8> = py
            .import("secrets")?
            .call_method1("token_bytes", (20usize,))?
            .extract()?;
        let handle: [u8; 20] = bytes
            .try_into()
            .map_err(|_| binding_err("secrets.token_bytes returned wrong length"))?;
        Ok(SamlArtifact {
            inner: gb::SamlArtifact::new(endpoint_index, entity_id, handle),
        })
    }
    /// Decode a base64 artifact string.
    #[staticmethod]
    fn decode(encoded: &str) -> PyResult<Self> {
        let inner = gb::SamlArtifact::decode(encoded).map_err(binding_err)?;
        Ok(SamlArtifact { inner })
    }
    /// Base64-encode this artifact.
    fn encode(&self) -> String {
        self.inner.encode()
    }
    fn matches_entity(&self, entity_id: &str) -> bool {
        self.inner.matches_entity(entity_id)
    }
    #[getter]
    fn endpoint_index(&self) -> u16 {
        self.inner.endpoint_index
    }
    #[getter]
    fn source_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.source_id)
    }
    #[getter]
    fn message_handle<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.message_handle)
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "bindings")?;
    m.add_class::<RedirectDecoded>()?;
    m.add_class::<PostDecoded>()?;
    m.add_class::<SamlArtifact>()?;
    m.add_function(wrap_pyfunction!(redirect_encode, &m)?)?;
    m.add_function(wrap_pyfunction!(redirect_decode, &m)?)?;
    m.add_function(wrap_pyfunction!(post_encode, &m)?)?;
    m.add_function(wrap_pyfunction!(post_decode, &m)?)?;
    m.add_function(wrap_pyfunction!(validate_relay_state, &m)?)?;
    m.add(
        "RELAY_STATE_MAX_BYTES",
        gb::relay_state::RELAY_STATE_MAX_BYTES,
    )?;
    Ok(())
}
