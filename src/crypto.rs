//! Bindings for `gamlastan::crypto` - keys, signing, verification, encryption,
//! decryption, canonicalization, and PKCS#11/HSM signing via `kryptering`.

use std::path::Path;
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use gamlastan::crypto as gx;
use gx::{KeyUsage, KeysManager as GKeysManager};

use crate::convert::new_submodule;
use crate::errors::crypto_err;

pub(crate) fn reject_weak_signature_algorithm(
    algorithm: &str,
    unsafe_allow_weak_sha1: bool,
) -> PyResult<()> {
    let normalized = algorithm.to_ascii_lowercase();
    if unsafe_allow_weak_sha1 || (!normalized.contains("sha1") && !normalized.contains("sha-1")) {
        return Ok(());
    }
    Err(crypto_err(
        "SHA-1 signature algorithms are disabled by default; pass \
         unsafe_allow_weak_sha1=True only for legacy interoperability",
    ))
}

// ---------------------------------------------------------------------------
// KeysManager
// ---------------------------------------------------------------------------

#[pyclass(
    module = "pygamlastan.crypto",
    name = "KeysManager",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct KeysManager {
    pub inner: GKeysManager,
}

#[pymethods]
impl KeysManager {
    #[new]
    fn new() -> Self {
        KeysManager {
            inner: GKeysManager::new(),
        }
    }

    /// Build an SP key manager: own signing key (PEM) + trusted IdP cert (PEM).
    #[staticmethod]
    fn build_sp(private_key_pem: &[u8], idp_certificate_pem: &[u8]) -> PyResult<Self> {
        let inner = gx::keys::build_sp_keys_manager(private_key_pem, idp_certificate_pem)
            .map_err(crypto_err)?;
        Ok(KeysManager { inner })
    }

    /// Build an IdP key manager from the IdP signing private key (PEM).
    #[staticmethod]
    fn build_idp(private_key_pem: &[u8]) -> PyResult<Self> {
        let inner = gx::keys::build_idp_keys_manager(private_key_pem).map_err(crypto_err)?;
        Ok(KeysManager { inner })
    }

    /// Load a private key from PEM and add it with the given usage
    /// ("sign", "verify", "encrypt", "decrypt", "any").
    ///
    /// SECURITY: `password` arrives as a Python `str`, which is immutable and
    /// cannot be zeroized; the caller cannot wipe it and copies may linger in
    /// the interpreter heap. Avoid logging it and keep its lifetime short.
    #[pyo3(signature = (pem, usage="sign", password=None))]
    fn add_key_pem(&mut self, pem: &[u8], usage: &str, password: Option<&str>) -> PyResult<()> {
        let mut key = gx::keys::loader::load_pem_auto(pem, password).map_err(crypto_err)?;
        key.usage = parse_key_usage(usage)?;
        self.inner.add_key(key);
        Ok(())
    }

    /// Add a trusted certificate (PEM or DER bytes) used to verify signatures.
    fn add_trusted_cert(&mut self, cert: Vec<u8>) {
        self.inner.add_trusted_cert(cert);
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

fn parse_key_usage(s: &str) -> PyResult<KeyUsage> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "sign" => KeyUsage::Sign,
        "verify" => KeyUsage::Verify,
        "encrypt" => KeyUsage::Encrypt,
        "decrypt" => KeyUsage::Decrypt,
        "any" => KeyUsage::Any,
        other => {
            return Err(crypto_err(format!("unknown key usage: {other}")));
        }
    })
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.crypto", name = "SamlSigner")]
pub struct SamlSigner {
    pub inner: gx::SamlSigner,
}

#[pymethods]
impl SamlSigner {
    /// File/PEM-key based signer from a KeysManager.
    #[new]
    fn new(keys: &KeysManager) -> Self {
        SamlSigner {
            inner: gx::SamlSigner::new(keys.inner.clone()),
        }
    }

    /// Convenience: build a signer directly from a signing private key PEM.
    #[staticmethod]
    #[pyo3(signature = (private_key_pem, password=None))]
    fn from_pem(private_key_pem: &[u8], password: Option<&str>) -> PyResult<Self> {
        let mut km = GKeysManager::new();
        let mut key =
            gx::keys::loader::load_pem_auto(private_key_pem, password).map_err(crypto_err)?;
        key.usage = KeyUsage::Sign;
        km.add_key(key);
        Ok(SamlSigner {
            inner: gx::SamlSigner::new(km),
        })
    }

    /// HSM/PKCS#11-backed signer. `keys` may be an empty KeysManager: with an
    /// HSM the private key lives on the token and the certificate that ends up
    /// in `<ds:KeyInfo>` comes from the signature template, so the manager need
    /// not hold any key material. `signer.inner` is an `Arc<dyn Signer>`, so the
    /// clone here just bumps a refcount - the underlying token session is shared.
    #[staticmethod]
    #[pyo3(signature = (signer, keys=None))]
    fn with_pkcs11(signer: &Pkcs11Signer, keys: Option<&KeysManager>) -> Self {
        let km = keys.map(|k| k.inner.clone()).unwrap_or_default();
        SamlSigner {
            inner: gx::SamlSigner::with_hsm_signer(km, signer.inner.clone()),
        }
    }

    /// Apply an enveloped XML-DSig signature to a document carrying a template.
    fn sign_enveloped(&self, xml_with_template: &str) -> PyResult<String> {
        self.inner
            .sign_enveloped(xml_with_template)
            .map_err(crypto_err)
    }

    /// Sign a HTTP-Redirect query string; returns the raw signature bytes.
    #[pyo3(signature = (query_string, algorithm_uri, unsafe_allow_weak_sha1=false))]
    fn sign_redirect_query<'py>(
        &self,
        py: Python<'py>,
        query_string: &[u8],
        algorithm_uri: &str,
        unsafe_allow_weak_sha1: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        reject_weak_signature_algorithm(algorithm_uri, unsafe_allow_weak_sha1)?;
        let sig = self
            .inner
            .sign_redirect_query(query_string, algorithm_uri)
            .map_err(crypto_err)?;
        Ok(PyBytes::new(py, &sig))
    }

    fn signature_method_uri(&self) -> PyResult<&'static str> {
        self.inner.signature_method_uri().map_err(crypto_err)
    }

    fn is_hsm_backed(&self) -> bool {
        self.inner.is_hsm_backed()
    }
}

// ---------------------------------------------------------------------------
// Verifier + VerifyResult
// ---------------------------------------------------------------------------

#[pyclass(
    module = "pygamlastan.crypto",
    name = "VerifyResult",
    frozen,
    skip_from_py_object
)]
#[derive(Clone)]
pub struct VerifyResult {
    inner: gx::VerifyResult,
}

#[pymethods]
impl VerifyResult {
    fn is_valid(&self) -> bool {
        self.inner.is_valid()
    }
    fn __bool__(&self) -> bool {
        self.inner.is_valid()
    }
    /// Reason string when invalid, else None.
    #[getter]
    fn reason(&self) -> Option<String> {
        match &self.inner {
            gx::VerifyResult::Invalid { reason } => Some(reason.clone()),
            _ => None,
        }
    }
    /// URIs of the verified references (with a leading '#' stripped) whose
    /// digest was actually checked. These are the cryptographically signed IDs.
    fn signed_reference_ids(&self) -> Vec<String> {
        match &self.inner {
            gx::VerifyResult::Valid { references, .. } => references
                .iter()
                .filter(|r| r.digest_verified)
                .map(|r| r.uri.strip_prefix('#').unwrap_or(&r.uri).to_string())
                .collect(),
            _ => Vec::new(),
        }
    }
    /// DER X.509 chain (leaf first) of the signing key, when valid.
    fn signing_cert_chain<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        match &self.inner {
            gx::VerifyResult::Valid { key_info, .. } => key_info
                .x509_chain
                .iter()
                .map(|c| PyBytes::new(py, c))
                .collect(),
            _ => Vec::new(),
        }
    }
}

#[pyclass(module = "pygamlastan.crypto", name = "SamlVerifier")]
pub struct SamlVerifier {
    inner: gx::SamlVerifier,
}

#[pymethods]
impl SamlVerifier {
    #[new]
    fn new(keys: &KeysManager) -> Self {
        SamlVerifier {
            inner: gx::SamlVerifier::new(keys.inner.clone()),
        }
    }

    /// Convenience: verifier trusting a single X.509 certificate (PEM or DER
    /// bytes). The certificate's public key is registered as a verification key.
    ///
    /// Two things must go into the manager, not one: the cert's public key (as a
    /// `Verify` key - without it the verifier reports "no keys in manager") AND
    /// the cert as a trust anchor (so the default `trusted_keys_only` mode does
    /// not blindly trust a certificate embedded in the signature's `<KeyInfo>`).
    /// PEM vs DER is detected by sniffing for the `-----BEGIN` armor.
    #[staticmethod]
    fn from_cert(cert: Vec<u8>) -> PyResult<Self> {
        let is_pem = cert.windows(10).any(|w| w == b"-----BEGIN");
        let mut key = if is_pem {
            gx::keys::loader::load_x509_cert_pem(&cert)
        } else {
            gx::keys::loader::load_x509_cert_der(&cert)
        }
        .map_err(crypto_err)?;
        key.usage = KeyUsage::Verify;
        let mut km = GKeysManager::new();
        km.add_key(key);
        km.add_trusted_cert(cert);
        Ok(SamlVerifier {
            inner: gx::SamlVerifier::new(km),
        })
    }

    #[pyo3(signature = (skip, unsafe_allow_skip_time_checks=false))]
    fn set_skip_time_checks(
        &mut self,
        py: Python<'_>,
        skip: bool,
        unsafe_allow_skip_time_checks: bool,
    ) -> PyResult<()> {
        if skip {
            if !unsafe_allow_skip_time_checks {
                return Err(crypto_err(
                    "skipping X.509 time checks is disabled by default; pass \
                     unsafe_allow_skip_time_checks=True only for legacy testing \
                     or emergency interoperability",
                ));
            }
            crate::convert::warn(
                py,
                "SamlVerifier.set_skip_time_checks(True) disables X.509 \
                 NotBefore/NotAfter validation; do not use in production.",
            );
        }
        self.inner.set_skip_time_checks(skip);
        Ok(())
    }
    #[pyo3(signature = (trusted, unsafe_allow_untrusted_keys=false))]
    fn set_trusted_keys_only(
        &mut self,
        py: Python<'_>,
        trusted: bool,
        unsafe_allow_untrusted_keys: bool,
    ) -> PyResult<()> {
        if !trusted {
            if !unsafe_allow_untrusted_keys {
                return Err(crypto_err(
                    "trusting certificates embedded in signature KeyInfo is \
                     disabled by default; pass unsafe_allow_untrusted_keys=True \
                     only for legacy unsafe processing",
                ));
            }
            crate::convert::warn(
                py,
                "SamlVerifier.set_trusted_keys_only(False) makes the verifier trust \
                 certificates embedded in the signature's KeyInfo; do not use in production.",
            );
        }
        self.inner.set_trusted_keys_only(trusted);
        Ok(())
    }
    #[pyo3(signature = (strict, unsafe_allow_non_strict=false))]
    fn set_strict_verification(
        &mut self,
        py: Python<'_>,
        strict: bool,
        unsafe_allow_non_strict: bool,
    ) -> PyResult<()> {
        if !strict {
            if !unsafe_allow_non_strict {
                return Err(crypto_err(
                    "non-strict XML signature verification is disabled by \
                     default; pass unsafe_allow_non_strict=True only for legacy \
                     unsafe processing",
                ));
            }
            crate::convert::warn(
                py,
                "SamlVerifier.set_strict_verification(False) disables XML Signature \
                 Wrapping (XSW) reference-position checks; do not use in production.",
            );
        }
        self.inner.set_strict_verification(strict);
        Ok(())
    }
    fn set_hmac_min_out_len(&mut self, bits: usize) {
        self.inner.set_hmac_min_out_len(bits);
    }

    /// Verify an enveloped XML-DSig signature; returns a VerifyResult.
    fn verify_enveloped(&self, signed_xml: &str) -> PyResult<VerifyResult> {
        let r = self
            .inner
            .verify_enveloped(signed_xml)
            .map_err(crypto_err)?;
        Ok(VerifyResult { inner: r })
    }

    /// Verify a HTTP-Redirect query signature.
    #[pyo3(signature = (query_string, signature, algorithm_uri, unsafe_allow_weak_sha1=false))]
    fn verify_redirect_query(
        &self,
        query_string: &[u8],
        signature: &[u8],
        algorithm_uri: &str,
        unsafe_allow_weak_sha1: bool,
    ) -> PyResult<bool> {
        reject_weak_signature_algorithm(algorithm_uri, unsafe_allow_weak_sha1)?;
        self.inner
            .verify_redirect_query(query_string, signature, algorithm_uri)
            .map_err(crypto_err)
    }
}

impl SamlVerifier {
    /// crate-internal: verify the enveloped signature over `signed_xml` and
    /// return the digest-verified reference IDs (the cryptographically signed
    /// element IDs, leading '#' stripped). Errors if the signature is invalid.
    ///
    /// This is the single point that binds `profiles.process_response_verified`
    /// to real crypto: the IDs it returns are exactly what may be passed as
    /// `verified_signed_ids` to the validator.
    pub(crate) fn verified_signed_ids(&self, signed_xml: &str) -> PyResult<Vec<String>> {
        match self
            .inner
            .verify_enveloped(signed_xml)
            .map_err(crypto_err)?
        {
            gx::VerifyResult::Valid { references, .. } => Ok(references
                .iter()
                .filter(|r| r.digest_verified)
                .map(|r| r.uri.strip_prefix('#').unwrap_or(&r.uri).to_string())
                .collect()),
            gx::VerifyResult::Invalid { reason } => Err(crypto_err(format!(
                "signature verification failed: {reason}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Encryptor / Decryptor
// ---------------------------------------------------------------------------

#[pyclass(module = "pygamlastan.crypto", name = "SamlEncryptor")]
pub struct SamlEncryptor {
    inner: gx::SamlEncryptor,
}

#[pymethods]
impl SamlEncryptor {
    #[new]
    fn new(keys: &KeysManager) -> Self {
        SamlEncryptor {
            inner: gx::SamlEncryptor::new(keys.inner.clone()),
        }
    }

    /// Encryptor that encrypts to a recipient certificate (DER) - PEFIM flow.
    #[staticmethod]
    fn for_certificate(cert_der: &[u8]) -> PyResult<Self> {
        let inner = gx::SamlEncryptor::for_certificate(cert_der).map_err(crypto_err)?;
        Ok(SamlEncryptor { inner })
    }

    fn encrypt(&self, template_xml: &str, plaintext: &[u8]) -> PyResult<String> {
        self.inner
            .encrypt(template_xml, plaintext)
            .map_err(crypto_err)
    }
}

#[pyclass(module = "pygamlastan.crypto", name = "SamlDecryptor")]
pub struct SamlDecryptor {
    inner: gx::SamlDecryptor,
}

#[pymethods]
impl SamlDecryptor {
    #[new]
    fn new(keys: &KeysManager) -> Self {
        SamlDecryptor {
            inner: gx::SamlDecryptor::new(keys.inner.clone()),
        }
    }

    fn decrypt(&self, encrypted_xml: &str) -> PyResult<String> {
        self.inner.decrypt(encrypted_xml).map_err(crypto_err)
    }

    fn decrypt_to_bytes<'py>(
        &self,
        py: Python<'py>,
        encrypted_xml: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let b = self
            .inner
            .decrypt_to_bytes(encrypted_xml)
            .map_err(crypto_err)?;
        Ok(PyBytes::new(py, &b))
    }
}

// ---------------------------------------------------------------------------
// Canonicalization
// ---------------------------------------------------------------------------

fn parse_c14n_mode(mode: &str) -> PyResult<gx::C14nMode> {
    Ok(match mode.to_ascii_lowercase().as_str() {
        "exclusive" | "exc" => gx::C14nMode::Exclusive,
        "inclusive" | "inc" => gx::C14nMode::Inclusive,
        "exclusive-with-comments" => gx::C14nMode::ExclusiveWithComments,
        "inclusive-with-comments" => gx::C14nMode::InclusiveWithComments,
        other => return Err(crypto_err(format!("unknown c14n mode: {other}"))),
    })
}

#[pyfunction]
#[pyo3(signature = (xml, mode="exclusive", inclusive_prefixes=None))]
fn canonicalize<'py>(
    py: Python<'py>,
    xml: &str,
    mode: &str,
    inclusive_prefixes: Option<Vec<String>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let prefixes = inclusive_prefixes.unwrap_or_default();
    let out = gx::canonicalize(xml, parse_c14n_mode(mode)?, &prefixes).map_err(crypto_err)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
#[pyo3(signature = (xml, inclusive_prefixes=None))]
fn exc_c14n<'py>(
    py: Python<'py>,
    xml: &str,
    inclusive_prefixes: Option<Vec<String>>,
) -> PyResult<Bound<'py, PyBytes>> {
    let prefixes = inclusive_prefixes.unwrap_or_default();
    let out = gx::exc_c14n(xml, &prefixes).map_err(crypto_err)?;
    Ok(PyBytes::new(py, &out))
}

// ---------------------------------------------------------------------------
// PKCS#11 (kryptering)
// ---------------------------------------------------------------------------

use kryptering::pkcs11::{
    Pkcs11Provider as KProvider, Pkcs11Session as KSession, Pkcs11Signer as KSigner,
};
use kryptering::{EcCurve, HashAlgorithm, SignatureAlgorithm};

/// Map a short, stable algorithm name to kryptering's `SignatureAlgorithm`.
///
/// We expose names (e.g. `"rsa-sha256"`, `"ecdsa-p256-sha256"`) rather than
/// binding the whole `SignatureAlgorithm`/`HashAlgorithm`/`EcCurve` enum tree as
/// Python classes - the string form is the entire knob a SAML caller needs and
/// keeps the surface small. Extend this match to support more algorithms.
fn parse_signature_algorithm(
    s: &str,
    unsafe_allow_weak_sha1: bool,
) -> PyResult<SignatureAlgorithm> {
    reject_weak_signature_algorithm(s, unsafe_allow_weak_sha1)?;
    use HashAlgorithm::*;
    Ok(match s.to_ascii_lowercase().as_str() {
        "rsa-sha1" => SignatureAlgorithm::RsaPkcs1v15(Sha1),
        "rsa-sha256" => SignatureAlgorithm::RsaPkcs1v15(Sha256),
        "rsa-sha384" => SignatureAlgorithm::RsaPkcs1v15(Sha384),
        "rsa-sha512" => SignatureAlgorithm::RsaPkcs1v15(Sha512),
        "rsa-pss-sha256" => SignatureAlgorithm::RsaPss(Sha256),
        "rsa-pss-sha384" => SignatureAlgorithm::RsaPss(Sha384),
        "rsa-pss-sha512" => SignatureAlgorithm::RsaPss(Sha512),
        "ecdsa-p256-sha256" => SignatureAlgorithm::Ecdsa(EcCurve::P256, Sha256),
        "ecdsa-p384-sha384" => SignatureAlgorithm::Ecdsa(EcCurve::P384, Sha384),
        "ecdsa-p521-sha512" => SignatureAlgorithm::Ecdsa(EcCurve::P521, Sha512),
        "ed25519" => SignatureAlgorithm::Ed25519,
        other => return Err(crypto_err(format!("unknown signature algorithm: {other}"))),
    })
}

#[pyclass(module = "pygamlastan.crypto", name = "Pkcs11Provider")]
pub struct Pkcs11Provider {
    inner: KProvider,
}

#[pymethods]
impl Pkcs11Provider {
    /// Load a PKCS#11 module (e.g. SoftHSM2 / kryoptic shared library).
    #[new]
    fn new(module_path: &str) -> PyResult<Self> {
        let inner = KProvider::new(Path::new(module_path)).map_err(crypto_err)?;
        Ok(Pkcs11Provider { inner })
    }

    /// Open and log in to a session with the given user PIN.
    ///
    /// SECURITY: `pin` arrives as a Python `str` and cannot be zeroized by the
    /// caller; avoid logging it and keep its lifetime short.
    fn open_session(&self, pin: &str) -> PyResult<Pkcs11Session> {
        let s = self.inner.open_session(pin).map_err(crypto_err)?;
        Ok(Pkcs11Session { inner: s })
    }
}

#[pyclass(module = "pygamlastan.crypto", name = "Pkcs11Session")]
pub struct Pkcs11Session {
    inner: KSession,
}

#[pymethods]
impl Pkcs11Session {
    /// Create a signer bound to the private key identified by `key_label`.
    /// `algorithm` is e.g. "rsa-sha256", "ecdsa-p256-sha256", "ed25519".
    #[pyo3(signature = (key_label, algorithm, unsafe_allow_weak_sha1=false))]
    fn signer(
        &self,
        key_label: &str,
        algorithm: &str,
        unsafe_allow_weak_sha1: bool,
    ) -> PyResult<Pkcs11Signer> {
        let alg = parse_signature_algorithm(algorithm, unsafe_allow_weak_sha1)?;
        let s = KSigner::new(&self.inner, key_label, alg).map_err(crypto_err)?;
        Ok(Pkcs11Signer { inner: Arc::new(s) })
    }
}

/// A signer bound to a private key on a PKCS#11 token.
///
/// Held as `Arc<dyn Signer>` (not the concrete `KSigner`) for two reasons: it is
/// the exact type `SamlSigner::with_hsm_signer` expects, and the `Arc` lets the
/// same token-backed signer be shared/cloned cheaply. `KSigner::new` clones the
/// session handle internally, so the wrapper owns everything it needs after
/// construction - the originating `Pkcs11Session` may be dropped. `Clone` is
/// derived (refcount bump); `skip_from_py_object` because it is only ever taken
/// by reference, never extracted from Python by value.
#[pyclass(
    module = "pygamlastan.crypto",
    name = "Pkcs11Signer",
    skip_from_py_object
)]
#[derive(Clone)]
pub struct Pkcs11Signer {
    inner: Arc<dyn kryptering::Signer>,
}

#[pymethods]
impl Pkcs11Signer {
    /// Construct directly from a session, key label, and algorithm name.
    #[new]
    #[pyo3(signature = (session, key_label, algorithm, unsafe_allow_weak_sha1=false))]
    fn new(
        session: &Pkcs11Session,
        key_label: &str,
        algorithm: &str,
        unsafe_allow_weak_sha1: bool,
    ) -> PyResult<Self> {
        let alg = parse_signature_algorithm(algorithm, unsafe_allow_weak_sha1)?;
        let s = KSigner::new(&session.inner, key_label, alg).map_err(crypto_err)?;
        Ok(Pkcs11Signer { inner: Arc::new(s) })
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "crypto")?;
    m.add_class::<KeysManager>()?;
    m.add_class::<SamlSigner>()?;
    m.add_class::<SamlVerifier>()?;
    m.add_class::<VerifyResult>()?;
    m.add_class::<SamlEncryptor>()?;
    m.add_class::<SamlDecryptor>()?;
    m.add_class::<Pkcs11Provider>()?;
    m.add_class::<Pkcs11Session>()?;
    m.add_class::<Pkcs11Signer>()?;
    m.add_function(wrap_pyfunction!(canonicalize, &m)?)?;
    m.add_function(wrap_pyfunction!(exc_c14n, &m)?)?;
    Ok(())
}
