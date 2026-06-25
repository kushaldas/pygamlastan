//! Bindings for `gamlastan::metadata` - parse SAML metadata, inspect endpoints
//! and keys, and serialize back to XML.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use gamlastan::metadata::types as gmt;
use gamlastan::metadata::types::{EntityDescriptor as GEntityDescriptor, KeyDescriptor};
use gamlastan::metadata::{EntitiesDescriptorRef, EntityDescriptorRef};
use gamlastan::xml::{parse_saml, uppsala, SamlSerialize};

use crate::convert::new_submodule;
use crate::errors::{metadata_err, xml_err};

/// A resolved metadata endpoint (Endpoint or IndexedEndpoint).
#[pyclass(module = "pygamlastan.metadata", name = "EndpointInfo", frozen)]
pub struct EndpointInfo {
    #[pyo3(get)]
    binding: String,
    #[pyo3(get)]
    location: String,
    #[pyo3(get)]
    response_location: Option<String>,
    #[pyo3(get)]
    index: Option<u16>,
    #[pyo3(get)]
    is_default: Option<bool>,
}

#[pymethods]
impl EndpointInfo {
    fn __repr__(&self) -> String {
        format!("EndpointInfo(binding={:?}, location={:?})", self.binding, self.location)
    }
}

fn ep(e: &gmt::Endpoint) -> EndpointInfo {
    EndpointInfo {
        binding: e.binding.clone(),
        location: e.location.clone(),
        response_location: e.response_location.clone(),
        index: None,
        is_default: None,
    }
}

fn indexed_ep(e: &gmt::IndexedEndpoint) -> EndpointInfo {
    EndpointInfo {
        binding: e.endpoint.binding.clone(),
        location: e.endpoint.location.clone(),
        response_location: e.endpoint.response_location.clone(),
        index: Some(e.index),
        is_default: e.is_default,
    }
}

/// Collect DER X.509 certs from a role's `<md:KeyDescriptor>`s, filtered by use.
///
/// Per SAML metadata (errata E62) a KeyDescriptor with no `use` attribute is
/// valid for *both* signing and encryption; `can_sign()` / `can_encrypt()`
/// already account for that, so a use-less descriptor appears in both lists.
fn certs_der<'py>(py: Python<'py>, kds: &[KeyDescriptor], signing: bool) -> Vec<Bound<'py, PyBytes>> {
    let mut out = Vec::new();
    for kd in kds {
        let usable = if signing { kd.can_sign() } else { kd.can_encrypt() };
        if usable {
            for der in kd.x509_certificates_der() {
                out.push(PyBytes::new(py, &der));
            }
        }
    }
    out
}

// NOTE on the accessors below: gamlastan models metadata as nested role
// descriptors. The key/endpoint data for an SSO role lives at
// `descriptor.sso_base.base.key_descriptors` (RoleDescriptorBase) and
// `descriptor.sso_base.{single_logout_services,name_id_formats}`
// (SsoDescriptorBase). The methods take a `role` string ("idp" or "sp", case-
// insensitive) and walk the matching descriptor list, flattening across however
// many descriptors of that role the entity declares.

#[pyclass(module = "pygamlastan.metadata", name = "EntityDescriptor", frozen)]
pub struct EntityDescriptor {
    pub inner: GEntityDescriptor,
}

impl EntityDescriptor {
    pub fn wrap(inner: GEntityDescriptor) -> Self {
        EntityDescriptor { inner }
    }
}

#[pymethods]
impl EntityDescriptor {
    #[getter]
    fn entity_id(&self) -> &str {
        &self.inner.entity_id
    }
    #[getter]
    fn valid_until(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.inner.valid_until
    }
    #[getter]
    fn has_signature(&self) -> bool {
        self.inner.has_signature
    }
    fn is_idp(&self) -> bool {
        self.inner.is_idp()
    }
    fn is_sp(&self) -> bool {
        self.inner.is_sp()
    }

    /// IdP SingleSignOnService endpoints.
    fn single_sign_on_services(&self) -> Vec<EndpointInfo> {
        let mut out = Vec::new();
        for idp in self.inner.idp_sso_descriptors() {
            out.extend(idp.single_sign_on_services.iter().map(ep));
        }
        out
    }

    /// SP AssertionConsumerService endpoints (indexed).
    fn assertion_consumer_services(&self) -> Vec<EndpointInfo> {
        let mut out = Vec::new();
        for sp in self.inner.sp_sso_descriptors() {
            out.extend(sp.assertion_consumer_services.iter().map(indexed_ep));
        }
        out
    }

    /// SingleLogoutService endpoints for the given role ("idp" or "sp").
    #[pyo3(signature = (role="idp"))]
    fn single_logout_services(&self, role: &str) -> Vec<EndpointInfo> {
        let mut out = Vec::new();
        if role.eq_ignore_ascii_case("idp") {
            for idp in self.inner.idp_sso_descriptors() {
                out.extend(idp.sso_base.single_logout_services.iter().map(ep));
            }
        } else {
            for sp in self.inner.sp_sso_descriptors() {
                out.extend(sp.sso_base.single_logout_services.iter().map(ep));
            }
        }
        out
    }

    /// NameIDFormat URIs advertised by the given role ("idp" or "sp").
    #[pyo3(signature = (role="idp"))]
    fn name_id_formats(&self, role: &str) -> Vec<String> {
        let mut out = Vec::new();
        if role.eq_ignore_ascii_case("idp") {
            for idp in self.inner.idp_sso_descriptors() {
                out.extend(idp.sso_base.name_id_formats.iter().cloned());
            }
        } else {
            for sp in self.inner.sp_sso_descriptors() {
                out.extend(sp.sso_base.name_id_formats.iter().cloned());
            }
        }
        out
    }

    /// DER X.509 signing certificates for the given role ("idp" or "sp").
    #[pyo3(signature = (role="idp"))]
    fn signing_certificates<'py>(&self, py: Python<'py>, role: &str) -> Vec<Bound<'py, PyBytes>> {
        if role.eq_ignore_ascii_case("idp") {
            self.inner
                .idp_sso_descriptors()
                .iter()
                .flat_map(|d| certs_der(py, &d.sso_base.base.key_descriptors, true))
                .collect()
        } else {
            self.inner
                .sp_sso_descriptors()
                .iter()
                .flat_map(|d| certs_der(py, &d.sso_base.base.key_descriptors, true))
                .collect()
        }
    }

    /// DER X.509 encryption certificates for the given role ("idp" or "sp").
    #[pyo3(signature = (role="sp"))]
    fn encryption_certificates<'py>(&self, py: Python<'py>, role: &str) -> Vec<Bound<'py, PyBytes>> {
        if role.eq_ignore_ascii_case("idp") {
            self.inner
                .idp_sso_descriptors()
                .iter()
                .flat_map(|d| certs_der(py, &d.sso_base.base.key_descriptors, false))
                .collect()
        } else {
            self.inner
                .sp_sso_descriptors()
                .iter()
                .flat_map(|d| certs_der(py, &d.sso_base.base.key_descriptors, false))
                .collect()
        }
    }

    /// Serialize back to metadata XML.
    fn to_xml(&self) -> PyResult<String> {
        self.inner.to_xml_string().map_err(xml_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "EntityDescriptor(entity_id={:?}, idp={}, sp={})",
            self.inner.entity_id,
            self.inner.is_idp(),
            self.inner.is_sp()
        )
    }
}

/// Parse a single `<md:EntityDescriptor>` document.
#[pyfunction]
fn parse_entity(xml: &str) -> PyResult<EntityDescriptor> {
    let doc = uppsala::parse(xml).map_err(xml_err)?;
    let r = parse_saml::<EntityDescriptorRef<'_>>(&doc).map_err(xml_err)?;
    Ok(EntityDescriptor::wrap(r.to_owned()))
}

/// Parse a `<md:EntitiesDescriptor>` aggregate into a list of EntityDescriptors.
#[pyfunction]
fn parse_entities(xml: &str) -> PyResult<Vec<EntityDescriptor>> {
    let doc = uppsala::parse(xml).map_err(xml_err)?;
    let r = parse_saml::<EntitiesDescriptorRef<'_>>(&doc).map_err(xml_err)?;
    let owned = r.to_owned();
    Ok(owned
        .entity_descriptors()
        .into_iter()
        .map(|e| EntityDescriptor::wrap(e.clone()))
        .collect())
}

/// Validate an EntityDescriptor against basic metadata requirements.
#[pyfunction]
fn validate_entity(entity: &EntityDescriptor) -> PyResult<()> {
    let validator = gamlastan::metadata::MetadataValidator::new();
    validator.validate(&entity.inner).map_err(metadata_err)
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "metadata")?;
    m.add_class::<EntityDescriptor>()?;
    m.add_class::<EndpointInfo>()?;
    m.add_function(wrap_pyfunction!(parse_entity, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_entities, &m)?)?;
    m.add_function(wrap_pyfunction!(validate_entity, &m)?)?;
    Ok(())
}
