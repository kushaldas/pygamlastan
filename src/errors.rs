//! Exception hierarchy for pygamlastan.
//!
//! A base `SamlError` with one subclass per gamlastan module error enum. Operation
//! failures raise these; security validation instead returns a structured
//! `ValidationResult` object (see `security` module).

use pyo3::prelude::*;
use pyo3::{create_exception, exceptions::PyException};

create_exception!(
    pygamlastan,
    SamlError,
    PyException,
    "Base class for all pygamlastan errors."
);
create_exception!(
    pygamlastan,
    SamlCoreError,
    SamlError,
    "Core SAML type error."
);
create_exception!(
    pygamlastan,
    SamlXmlError,
    SamlError,
    "XML parsing/serialization error."
);
create_exception!(
    pygamlastan,
    SamlCryptoError,
    SamlError,
    "Cryptographic operation error."
);
create_exception!(
    pygamlastan,
    SamlBindingError,
    SamlError,
    "Protocol binding error."
);
create_exception!(pygamlastan, SamlMetadataError, SamlError, "Metadata error.");
create_exception!(
    pygamlastan,
    SamlSecurityError,
    SamlError,
    "Security validation error."
);
create_exception!(
    pygamlastan,
    SamlProfileError,
    SamlError,
    "SAML profile error."
);
create_exception!(
    pygamlastan,
    SamlPolicyError,
    SamlError,
    "Attribute-release policy error."
);
create_exception!(
    pygamlastan,
    SamlIdentError,
    SamlError,
    "Identity store error."
);

// --- Error-mapping helpers (gamlastan/kryptering error enums -> PyErr) ---
// The orphan rule prevents `impl From<ForeignError> for PyErr`, so we use small
// helper functions and `.map_err(...)` at call sites.

// Some helpers map error enums that aren't surfaced yet by the current binding
// surface (e.g. policy/ident paths). `#[allow(dead_code)]` on those keeps the
// build warning-clean while preserving the full hierarchy for forward use.
use std::fmt::Display;

pub fn core_err<E: Display>(e: E) -> PyErr {
    SamlCoreError::new_err(e.to_string())
}
pub fn xml_err<E: Display>(e: E) -> PyErr {
    SamlXmlError::new_err(e.to_string())
}
pub fn crypto_err<E: Display>(e: E) -> PyErr {
    SamlCryptoError::new_err(e.to_string())
}
pub fn binding_err<E: Display>(e: E) -> PyErr {
    SamlBindingError::new_err(e.to_string())
}
pub fn metadata_err<E: Display>(e: E) -> PyErr {
    SamlMetadataError::new_err(e.to_string())
}
#[allow(dead_code)]
pub fn security_err<E: Display>(e: E) -> PyErr {
    SamlSecurityError::new_err(e.to_string())
}
pub fn profile_err<E: Display>(e: E) -> PyErr {
    SamlProfileError::new_err(e.to_string())
}
#[allow(dead_code)]
pub fn policy_err<E: Display>(e: E) -> PyErr {
    SamlPolicyError::new_err(e.to_string())
}
#[allow(dead_code)]
pub fn ident_err<E: Display>(e: E) -> PyErr {
    SamlIdentError::new_err(e.to_string())
}

/// Register exception types on the top-level module.
pub fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("SamlError", py.get_type::<SamlError>())?;
    m.add("SamlCoreError", py.get_type::<SamlCoreError>())?;
    m.add("SamlXmlError", py.get_type::<SamlXmlError>())?;
    m.add("SamlCryptoError", py.get_type::<SamlCryptoError>())?;
    m.add("SamlBindingError", py.get_type::<SamlBindingError>())?;
    m.add("SamlMetadataError", py.get_type::<SamlMetadataError>())?;
    m.add("SamlSecurityError", py.get_type::<SamlSecurityError>())?;
    m.add("SamlProfileError", py.get_type::<SamlProfileError>())?;
    m.add("SamlPolicyError", py.get_type::<SamlPolicyError>())?;
    m.add("SamlIdentError", py.get_type::<SamlIdentError>())?;
    Ok(())
}
