//! pygamlastan - Python bindings for the gamlastan SAML 2.0 library.
//!
//! The binding follows an "owned-only at the boundary" model: parsing produces a
//! borrowed `*Ref<'a>` view tied to the XML document, which is immediately converted
//! to its owned variant via `.to_owned()` before being handed to Python. No Rust
//! lifetime ever escapes into a Python object.

use pyo3::prelude::*;

mod attribute_map;
mod bindings;
mod convert;
mod core;
mod crypto;
mod errors;
mod idp;
mod metadata;
mod profiles;
mod security;
mod xml;

/// Native extension entry point. Installed as `pygamlastan._native` and
/// re-exported by the `pygamlastan` Python package. Each gamlastan area is a
/// submodule registered as `pygamlastan.core`, `pygamlastan.crypto`, ...
#[pymodule]
fn _native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    errors::register(py, m)?;
    core::register(py, m)?;
    crypto::register(py, m)?;
    xml::register(py, m)?;
    bindings::register(py, m)?;
    metadata::register(py, m)?;
    attribute_map::register(py, m)?;
    security::register(py, m)?;
    profiles::register(py, m)?;
    idp::register(py, m)?;
    Ok(())
}
