//! Bindings for `gamlastan::metadata` - parse SAML metadata, inspect endpoints
//! and keys, and serialize back to XML.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use gamlastan::idp::policy::sp_attribute_requirements;
use gamlastan::metadata::types as gmt;
use gamlastan::metadata::types::{
    EntityDescriptor as GEntityDescriptor, KeyDescriptor, UiInfo as GUiInfo, UiLogo as GUiLogo,
};
use gamlastan::metadata::{EntitiesDescriptorRef, EntityDescriptorRef};
use gamlastan::xml::{parse_saml, parse_secure, SamlSerialize};

use crate::convert::new_submodule;
use crate::core::Attribute;
use crate::errors::{metadata_err, xml_err};

/// One `mdui:Logo` (URL with optional dimensions and language).
#[pyclass(module = "pygamlastan.metadata", name = "UiLogo", frozen)]
pub struct UiLogo {
    #[pyo3(get)]
    url: String,
    #[pyo3(get)]
    width: Option<u32>,
    #[pyo3(get)]
    height: Option<u32>,
    #[pyo3(get)]
    lang: Option<String>,
}

/// Parsed `mdui:UIInfo` - the display metadata (name, logo, description) an SP
/// or IdP publishes for consent and discovery UIs. Localized fields are lists of
/// `(lang, value)` tuples in document order; `lang` may be `None`.
#[pyclass(module = "pygamlastan.metadata", name = "UiInfo", frozen)]
pub struct UiInfo {
    inner: GUiInfo,
}

fn localized(items: &[gmt::LocalizedText]) -> Vec<(Option<String>, String)> {
    items
        .iter()
        .map(|t| (t.lang.clone(), t.value.clone()))
        .collect()
}

#[pymethods]
impl UiInfo {
    #[getter]
    fn display_names(&self) -> Vec<(Option<String>, String)> {
        localized(&self.inner.display_names)
    }
    #[getter]
    fn descriptions(&self) -> Vec<(Option<String>, String)> {
        localized(&self.inner.descriptions)
    }
    #[getter]
    fn information_urls(&self) -> Vec<(Option<String>, String)> {
        localized(&self.inner.information_urls)
    }
    #[getter]
    fn privacy_statement_urls(&self) -> Vec<(Option<String>, String)> {
        localized(&self.inner.privacy_statement_urls)
    }
    #[getter]
    fn keywords(&self) -> Vec<(Option<String>, String)> {
        localized(&self.inner.keywords)
    }
    #[getter]
    fn logos(&self) -> Vec<UiLogo> {
        self.inner
            .logos
            .iter()
            .map(|l: &GUiLogo| UiLogo {
                url: l.url.clone(),
                width: l.width,
                height: l.height,
                lang: l.lang.clone(),
            })
            .collect()
    }
}

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
        format!(
            "EndpointInfo(binding={:?}, location={:?})",
            self.binding, self.location
        )
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
fn certs_der<'py>(
    py: Python<'py>,
    kds: &[KeyDescriptor],
    signing: bool,
) -> Vec<Bound<'py, PyBytes>> {
    let mut out = Vec::new();
    for kd in kds {
        let usable = if signing {
            kd.can_sign()
        } else {
            kd.can_encrypt()
        };
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
    fn encryption_certificates<'py>(
        &self,
        py: Python<'py>,
        role: &str,
    ) -> Vec<Bound<'py, PyBytes>> {
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

    /// The `mdrpi:RegistrationInfo/@registrationAuthority`, if present (the
    /// federation operator that registered this entity).
    #[getter]
    fn registration_authority(&self) -> Option<String> {
        self.inner.registration_authority()
    }

    /// The published entity-category URIs (`mdattr:EntityAttributes`,
    /// `http://macedir.org/entity-category`).
    fn entity_categories(&self) -> Vec<String> {
        self.inner.entity_categories()
    }

    /// All values of the named entity attribute from `mdattr:EntityAttributes`
    /// (e.g. `urn:oasis:names:tc:SAML:profiles:subject-id:req`).
    fn entity_attribute_values(&self, name: &str) -> Vec<String> {
        self.inner.entity_attribute_values(name)
    }

    /// Every entity attribute as `(name, values)` pairs, in document order.
    fn entity_attributes(&self) -> Vec<(String, Vec<String>)> {
        self.inner.md_extensions().entity_attributes.clone()
    }

    /// Algorithm URIs advertised via `alg:SigningMethod` / `alg:DigestMethod`,
    /// across the entity and its SSO roles, de-duplicated in document order.
    fn supported_algorithms(&self) -> Vec<String> {
        self.inner.supported_algorithms()
    }

    /// The `mdui:UIInfo` (display name / logo / description) for the given role
    /// ("sp" or "idp"), if published. Falls back to entity-level Extensions.
    #[pyo3(signature = (role="sp"))]
    fn ui_info(&self, role: &str) -> Option<UiInfo> {
        let info = if role.eq_ignore_ascii_case("idp") {
            self.inner.idp_ui_info()
        } else {
            self.inner.sp_ui_info()
        };
        info.map(|inner| UiInfo { inner })
    }

    /// The SP's requested attributes as `(required, optional)`, read from its
    /// `AttributeConsumingService` (the one at `acs_index`, else the default).
    /// Each is a list of `core.Attribute` (a requested value list narrows the
    /// released values). Feed these into `idp.ReleasePolicy.filter`.
    #[pyo3(signature = (acs_index=None))]
    fn requested_attributes(&self, acs_index: Option<u16>) -> (Vec<Attribute>, Vec<Attribute>) {
        let mut required = Vec::new();
        let mut optional = Vec::new();
        for sp in self.inner.sp_sso_descriptors() {
            let (req, opt) = sp_attribute_requirements(sp, acs_index);
            required.extend(req.into_iter().map(|r| Attribute::wrap(r.attribute)));
            optional.extend(opt.into_iter().map(|r| Attribute::wrap(r.attribute)));
        }
        (required, optional)
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
///
/// SECURITY: remote/published metadata is attacker-influenced, so parsing goes
/// through `parse_secure` (uppsala 0.5 resource limits + DTD/XXE rejection).
#[pyfunction]
fn parse_entity(xml: &str) -> PyResult<EntityDescriptor> {
    let doc = parse_secure(xml).map_err(xml_err)?;
    let r = parse_saml::<EntityDescriptorRef<'_>>(&doc).map_err(xml_err)?;
    Ok(EntityDescriptor::wrap(r.to_owned()))
}

/// Parse a `<md:EntitiesDescriptor>` aggregate into a list of EntityDescriptors.
#[pyfunction]
fn parse_entities(xml: &str) -> PyResult<Vec<EntityDescriptor>> {
    let doc = parse_secure(xml).map_err(xml_err)?;
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
    m.add_class::<UiInfo>()?;
    m.add_class::<UiLogo>()?;
    m.add_function(wrap_pyfunction!(parse_entity, &m)?)?;
    m.add_function(wrap_pyfunction!(parse_entities, &m)?)?;
    m.add_function(wrap_pyfunction!(validate_entity, &m)?)?;
    Ok(())
}
