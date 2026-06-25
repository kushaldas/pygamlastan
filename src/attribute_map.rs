//! Bindings for `gamlastan::attribute_map` - wire ⇄ local attribute-name
//! conversion using the shipped maps (saml_uri, basic, shibboleth, adfs).

use pyo3::prelude::*;
use pyo3::types::PyModule;

use gamlastan::attribute_map as gam;

use crate::convert::new_submodule;
use crate::core::{Attribute, NameId};
use crate::errors::core_err;

fn static_map(name: &str) -> PyResult<&'static gam::StaticAttributeMap> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "saml_uri" => &gam::SAML_URI,
        "basic" => &gam::BASIC,
        "shibboleth_uri" => &gam::SHIBBOLETH_URI,
        "adfs_v1x" => &gam::ADFS_V1X,
        "adfs_v20" => &gam::ADFS_V20,
        other => return Err(core_err(format!("unknown attribute map: {other}"))),
    })
}

#[pyclass(module = "pygamlastan.attribute_map", name = "AttributeConverter")]
pub struct AttributeConverter {
    inner: gam::AttributeConverter,
}

#[pymethods]
impl AttributeConverter {
    #[new]
    fn new(name_format: String) -> Self {
        AttributeConverter {
            inner: gam::AttributeConverter::new(name_format),
        }
    }
    /// Build a converter from a shipped static map name (e.g. "saml_uri").
    #[staticmethod]
    fn from_static(name: &str) -> PyResult<Self> {
        Ok(AttributeConverter {
            inner: gam::AttributeConverter::from_static(static_map(name)?),
        })
    }
    fn add_mapping(&mut self, wire: &str, local: &str) {
        self.inner.add_mapping(wire, local);
    }
    #[getter]
    fn name_format(&self) -> &str {
        self.inner.name_format()
    }
    fn to_local_name(&self, wire_name: &str) -> Option<String> {
        self.inner.to_local_name(wire_name).map(|s| s.to_string())
    }
    fn to_wire_name(&self, local_name: &str) -> Option<String> {
        self.inner.to_wire_name(local_name).map(|s| s.to_string())
    }
}

#[pyclass(
    module = "pygamlastan.attribute_map",
    name = "LocalAttribute",
    from_py_object
)]
#[derive(Clone)]
pub struct LocalAttribute {
    inner: gam::LocalAttribute,
}

#[pymethods]
impl LocalAttribute {
    #[new]
    fn new(name: String, values: Vec<String>) -> Self {
        let refs: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
        LocalAttribute {
            inner: gam::LocalAttribute::from_strings(name, &refs),
        }
    }
    #[getter]
    fn name(&self) -> &str {
        &self.inner.name
    }
    /// String-typed values of this attribute.
    #[getter]
    fn values(&self) -> Vec<String> {
        self.inner
            .values
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    }
    fn __repr__(&self) -> String {
        format!("LocalAttribute(name={:?})", self.inner.name)
    }
}

#[pyclass(module = "pygamlastan.attribute_map", name = "AttributeConverterSet")]
pub struct AttributeConverterSet {
    inner: gam::AttributeConverterSet,
    allow_unknown_attributes: bool,
}

#[pymethods]
impl AttributeConverterSet {
    /// Converter set preloaded with all shipped default maps.
    #[staticmethod]
    #[pyo3(signature = (allow_unknown_attributes=false))]
    fn with_default_maps(allow_unknown_attributes: bool) -> Self {
        let inner = gam::AttributeConverterSet::with_default_maps()
            .allow_unknown_attributes(allow_unknown_attributes);
        AttributeConverterSet {
            inner,
            allow_unknown_attributes,
        }
    }

    /// Convert wire `Attribute`s into local (name, values) attributes.
    fn to_local(&self, attributes: Vec<Attribute>) -> Vec<LocalAttribute> {
        let owned: Vec<_> = attributes
            .into_iter()
            .map(|a| {
                let mut attr = a.inner;
                if !self.allow_unknown_attributes {
                    attr.friendly_name = None;
                }
                attr
            })
            .collect();
        self.inner
            .to_local(&owned)
            .into_iter()
            .map(|inner| LocalAttribute { inner })
            .collect()
    }

    /// Convert local attributes back into wire `Attribute`s for `name_format`.
    #[allow(clippy::wrong_self_convention)]
    fn from_local(&self, ava: Vec<LocalAttribute>, name_format: &str) -> Vec<Attribute> {
        let owned: Vec<_> = ava.into_iter().map(|a| a.inner).collect();
        self.inner
            .from_local(&owned, name_format)
            .into_iter()
            .map(Attribute::wrap)
            .collect()
    }

    /// The local name for a wire attribute, if a converter knows it.
    fn local_name(&self, attribute: &Attribute) -> Option<String> {
        if self.allow_unknown_attributes {
            return self.inner.local_name(&attribute.inner);
        }
        let mut attr = attribute.inner.clone();
        attr.friendly_name = None;
        self.inner.local_name(&attr)
    }
}

/// Build an eduPersonTargetedID attribute from a list of NameIds.
#[pyfunction]
fn eptid_attribute(name_ids: Vec<NameId>) -> Attribute {
    let owned: Vec<_> = name_ids.into_iter().map(|n| n.inner).collect();
    Attribute::wrap(gam::eptid_attribute(owned))
}

/// Extract the NameIds from an eduPersonTargetedID attribute.
#[pyfunction]
fn eptid_name_ids(attribute: &Attribute) -> Vec<NameId> {
    gam::eptid_name_ids(&attribute.inner)
        .into_iter()
        .map(|n| NameId::wrap(n.clone()))
        .collect()
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = new_submodule(py, parent, "attribute_map")?;
    m.add_class::<AttributeConverter>()?;
    m.add_class::<AttributeConverterSet>()?;
    m.add_class::<LocalAttribute>()?;
    m.add_function(wrap_pyfunction!(eptid_attribute, &m)?)?;
    m.add_function(wrap_pyfunction!(eptid_name_ids, &m)?)?;
    m.add("EPTID_OID", gam::EPTID_OID)?;
    Ok(())
}
