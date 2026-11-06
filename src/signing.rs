//! Bindings for gamlastan's signature and digest algorithm selection.
//!
//! `SignatureMethod` and `DigestMethod` are closed sets of strong algorithms
//! (SHA-2 RSA and ECDSA); SHA-1, MD5 and the like are not representable, so
//! neither configuration nor an SP's metadata can select them.
//! `SigningPreference` is an IdP's ordered preference, set per SP with
//! `PolicyEntry(signing_preference=...)` and resolved per response against what
//! the SP advertises in its metadata.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use gamlastan::crypto as gc;

/// An XML-DSig signature algorithm gamlastan will emit.
#[pyclass(
    module = "pygamlastan.crypto",
    name = "SignatureMethod",
    frozen,
    eq,
    eq_int,
    hash,
    from_py_object,
    rename_all = "SCREAMING_SNAKE_CASE"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SignatureMethod {
    RsaSha256,
    RsaSha384,
    RsaSha512,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
}

impl From<gc::SignatureMethod> for SignatureMethod {
    fn from(m: gc::SignatureMethod) -> Self {
        match m {
            gc::SignatureMethod::RsaSha256 => SignatureMethod::RsaSha256,
            gc::SignatureMethod::RsaSha384 => SignatureMethod::RsaSha384,
            gc::SignatureMethod::RsaSha512 => SignatureMethod::RsaSha512,
            gc::SignatureMethod::EcdsaSha256 => SignatureMethod::EcdsaSha256,
            gc::SignatureMethod::EcdsaSha384 => SignatureMethod::EcdsaSha384,
            gc::SignatureMethod::EcdsaSha512 => SignatureMethod::EcdsaSha512,
        }
    }
}

impl From<SignatureMethod> for gc::SignatureMethod {
    fn from(m: SignatureMethod) -> Self {
        match m {
            SignatureMethod::RsaSha256 => gc::SignatureMethod::RsaSha256,
            SignatureMethod::RsaSha384 => gc::SignatureMethod::RsaSha384,
            SignatureMethod::RsaSha512 => gc::SignatureMethod::RsaSha512,
            SignatureMethod::EcdsaSha256 => gc::SignatureMethod::EcdsaSha256,
            SignatureMethod::EcdsaSha384 => gc::SignatureMethod::EcdsaSha384,
            SignatureMethod::EcdsaSha512 => gc::SignatureMethod::EcdsaSha512,
        }
    }
}

#[pymethods]
impl SignatureMethod {
    /// The XML-DSig algorithm URI.
    #[getter]
    fn uri(&self) -> &'static str {
        gc::SignatureMethod::from(*self).uri()
    }
    /// The method for an algorithm URI, or `None` if gamlastan does not emit it
    /// (every weak or unknown algorithm).
    #[staticmethod]
    fn from_uri(uri: &str) -> Option<Self> {
        gc::SignatureMethod::from_uri(uri).map(Self::from)
    }
}

/// An XML-DSig digest algorithm gamlastan will emit.
#[pyclass(
    module = "pygamlastan.crypto",
    name = "DigestMethod",
    frozen,
    eq,
    eq_int,
    hash,
    from_py_object,
    rename_all = "SCREAMING_SNAKE_CASE"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum DigestMethod {
    Sha256,
    Sha384,
    Sha512,
}

impl From<gc::DigestMethod> for DigestMethod {
    fn from(m: gc::DigestMethod) -> Self {
        match m {
            gc::DigestMethod::Sha256 => DigestMethod::Sha256,
            gc::DigestMethod::Sha384 => DigestMethod::Sha384,
            gc::DigestMethod::Sha512 => DigestMethod::Sha512,
        }
    }
}

impl From<DigestMethod> for gc::DigestMethod {
    fn from(m: DigestMethod) -> Self {
        match m {
            DigestMethod::Sha256 => gc::DigestMethod::Sha256,
            DigestMethod::Sha384 => gc::DigestMethod::Sha384,
            DigestMethod::Sha512 => gc::DigestMethod::Sha512,
        }
    }
}

#[pymethods]
impl DigestMethod {
    /// The XML-DSig algorithm URI.
    #[getter]
    fn uri(&self) -> &'static str {
        gc::DigestMethod::from(*self).uri()
    }
    /// The method for an algorithm URI, or `None` if gamlastan does not emit it.
    #[staticmethod]
    fn from_uri(uri: &str) -> Option<Self> {
        gc::DigestMethod::from_uri(uri).map(Self::from)
    }
}

/// The signature and digest algorithms chosen for one response; `None` leaves
/// that kind at the signer's default.
#[pyclass(module = "pygamlastan.crypto", name = "SigningAlgorithms", frozen)]
pub struct SigningAlgorithms {
    inner: gc::SigningAlgorithms,
}

#[pymethods]
impl SigningAlgorithms {
    #[getter]
    fn signature(&self) -> Option<SignatureMethod> {
        self.inner.signature.map(SignatureMethod::from)
    }
    #[getter]
    fn digest(&self) -> Option<DigestMethod> {
        self.inner.digest.map(DigestMethod::from)
    }
}

/// An IdP's ordered preference for signature and digest algorithms.
///
/// For each kind the first entry the SP also advertises wins; if the SP
/// advertises none of them (or nothing), the first entry wins. An empty list
/// leaves that kind at the signer's default. The SP's advertisement is an
/// untrusted claim: it only chooses among the IdP's own entries and can never
/// add one. Signatures are matched against ``alg:SigningMethod`` entries and
/// digests against ``alg:DigestMethod`` entries, separately.
///
/// With an HSM-backed signer, list only the token's own signature method: a
/// response that resolves to another one fails (denials included), for the SPs
/// that resolve to it, when it is signed.
#[pyclass(
    module = "pygamlastan.crypto",
    name = "SigningPreference",
    frozen,
    from_py_object
)]
#[derive(Clone)]
pub struct SigningPreference {
    pub(crate) inner: gc::SigningPreference,
}

#[pymethods]
impl SigningPreference {
    #[new]
    #[pyo3(signature = (signature_methods=None, digest_methods=None))]
    fn new(
        signature_methods: Option<Vec<SignatureMethod>>,
        digest_methods: Option<Vec<DigestMethod>>,
    ) -> Self {
        SigningPreference {
            inner: gc::SigningPreference::new()
                .with_signature_methods(
                    signature_methods
                        .unwrap_or_default()
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                )
                .with_digest_methods(
                    digest_methods
                        .unwrap_or_default()
                        .into_iter()
                        .map(Into::into)
                        .collect(),
                ),
        }
    }

    /// Resolve against the algorithm URIs an SP advertises in its metadata
    /// (``alg:SigningMethod`` for the signature, ``alg:DigestMethod`` for the
    /// digest). A URI placed under the wrong element does not count.
    #[pyo3(signature = (sp_signature_methods=None, sp_digest_methods=None))]
    fn resolve(
        &self,
        sp_signature_methods: Option<Vec<String>>,
        sp_digest_methods: Option<Vec<String>>,
    ) -> SigningAlgorithms {
        SigningAlgorithms {
            inner: self.inner.resolve(
                &sp_signature_methods.unwrap_or_default(),
                &sp_digest_methods.unwrap_or_default(),
            ),
        }
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SignatureMethod>()?;
    m.add_class::<DigestMethod>()?;
    m.add_class::<SigningAlgorithms>()?;
    m.add_class::<SigningPreference>()?;
    Ok(())
}
