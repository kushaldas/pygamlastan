//! Bindings for `gamlastan::xml` - parse SAML XML into owned core types.
//!
//! Each `parse_*` function parses a SAML XML string into a borrowed `*Ref`, then
//! immediately converts to the owned variant (`.to_owned()`) so no XML-document
//! lifetime escapes into Python.
//!
//! SECURITY: every entry point here parses *attacker-controlled* XML, so all of
//! them go through `gamlastan::xml::parse_secure` rather than the raw
//! `uppsala::parse`. `parse_secure` layers two defenses on top of the parse:
//! (1) uppsala 0.5's fail-closed resource limits - element-nesting depth (128),
//! entity-expansion byte budget (1 MiB), and entity-nesting depth (256), which
//! bound billion-laughs / quadratic-blowup amplification and deep-nesting stack
//! exhaustion; and (2) outright rejection of any document carrying a DTD
//! (`<!DOCTYPE ...>`), removing the XXE / entity-smuggling entry point. A
//! rejected document raises `SamlXmlError`.

use pyo3::prelude::*;
use pyo3::types::PyModule;

use gamlastan::core::assertion::types::AssertionRef;
use gamlastan::core::protocol::{
    AuthnRequestRef, LogoutRequestRef, LogoutResponseRef, ResponseRef,
};
use gamlastan::xml::{parse_saml, parse_secure};

use crate::convert::new_submodule;
use crate::core::{Assertion, AuthnRequest, LogoutRequest, LogoutResponse, Response};
use crate::errors::xml_err;

/// Parse a `<samlp:Response>` document into an owned `Response`.
#[pyfunction]
fn parse_response(xml: &str) -> PyResult<Response> {
    let doc = parse_secure(xml).map_err(xml_err)?;
    let r = parse_saml::<ResponseRef<'_>>(&doc).map_err(xml_err)?;
    Ok(Response::wrap(r.to_owned()))
}

/// Parse a `<samlp:AuthnRequest>` document into an owned `AuthnRequest`.
#[pyfunction]
fn parse_authn_request(xml: &str) -> PyResult<AuthnRequest> {
    let doc = parse_secure(xml).map_err(xml_err)?;
    let r = parse_saml::<AuthnRequestRef<'_>>(&doc).map_err(xml_err)?;
    Ok(AuthnRequest::wrap(r.to_owned()))
}

/// Parse a standalone `<saml:Assertion>` document into an owned `Assertion`.
#[pyfunction]
fn parse_assertion(xml: &str) -> PyResult<Assertion> {
    let doc = parse_secure(xml).map_err(xml_err)?;
    let r = parse_saml::<AssertionRef<'_>>(&doc).map_err(xml_err)?;
    Ok(Assertion::wrap(r.to_owned()))
}

/// Parse a `<samlp:LogoutRequest>` document into an owned `LogoutRequest`.
#[pyfunction]
fn parse_logout_request(xml: &str) -> PyResult<LogoutRequest> {
    let doc = parse_secure(xml).map_err(xml_err)?;
    let r = parse_saml::<LogoutRequestRef<'_>>(&doc).map_err(xml_err)?;
    Ok(LogoutRequest::wrap(r.to_owned()))
}

/// Parse a `<samlp:LogoutResponse>` document into an owned `LogoutResponse`.
#[pyfunction]
fn parse_logout_response(xml: &str) -> PyResult<LogoutResponse> {
    let doc = parse_secure(xml).map_err(xml_err)?;
    let r = parse_saml::<LogoutResponseRef<'_>>(&doc).map_err(xml_err)?;
    Ok(LogoutResponse::wrap(r.to_owned()))
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "xml")?;
    m.add_function(wrap_pyfunction!(parse_response, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_authn_request, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_assertion, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_logout_request, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_logout_response, &m)?)?;
    Ok(())
}
