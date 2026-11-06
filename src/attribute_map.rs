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
    /// Build a converter from independent inbound and outbound maps, the shape
    /// of a pysaml2 attribute map (``MAP["fro"]`` and ``MAP["to"]``).
    ///
    /// ``fro`` holds ``(wire name, local name)`` pairs and ``to`` holds
    /// ``(local name, wire name)`` pairs. Use this, not ``add_mapping``, for a
    /// map whose two directions differ. Real maps do: one production
    /// ``saml_uri`` map has 83 inbound and 99 outbound entries. Mirroring one would
    /// make an SP-supplied attribute name resolve to a local attribute it did not
    /// before, and where several wire names share a local name it would make the
    /// outbound name depend on insertion order. A key that repeats within one
    /// direction keeps its later entry.
    #[staticmethod]
    #[pyo3(signature = (name_format, fro=None, to=None))]
    fn from_directions(
        name_format: String,
        fro: Option<Vec<(String, String)>>,
        to: Option<Vec<(String, String)>>,
    ) -> Self {
        let fro = fro.unwrap_or_default();
        let to = to.unwrap_or_default();
        let fro: Vec<(&str, &str)> = fro.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let to: Vec<(&str, &str)> = to.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        AttributeConverter {
            inner: gam::AttributeConverter::from_directions(name_format, &fro, &to),
        }
    }
    /// Add one wire <-> local mapping in both directions. Only for a map that
    /// really is symmetric; see ``from_directions``.
    fn add_mapping(&mut self, wire: &str, local: &str) {
        self.inner.add_mapping(wire, local);
    }
    /// Add one inbound entry: a received ``wire`` name resolves to ``local``. The
    /// reverse is not added, so ``local`` is not sent as ``wire`` unless an
    /// outbound entry says so.
    fn add_wire_to_local(&mut self, wire: &str, local: &str) {
        self.inner.add_wire_to_local(wire, local);
    }
    /// Add one outbound entry: ``local`` is sent as ``wire``. The reverse is not
    /// added, so a received ``wire`` is not recognised as ``local`` unless an
    /// inbound entry says so.
    fn add_local_to_wire(&mut self, local: &str, wire: &str) {
        self.inner.add_local_to_wire(local, wire);
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
    pub(crate) inner: gam::AttributeConverterSet,
    allow_unknown_attributes: bool,
}

#[pymethods]
impl AttributeConverterSet {
    /// A set from your own converters (for example maps loaded from a pysaml2
    /// ``attribute_map_dir``). The converters are copied: later changes to them
    /// are not seen by the set. With ``allow_unknown_attributes``, names that no
    /// converter knows pass through instead of being dropped.
    #[new]
    #[pyo3(signature = (converters, allow_unknown_attributes=false))]
    fn new(converters: Vec<PyRef<'_, AttributeConverter>>, allow_unknown_attributes: bool) -> Self {
        let inner =
            gam::AttributeConverterSet::new(converters.iter().map(|c| c.inner.clone()).collect())
                .allow_unknown_attributes(allow_unknown_attributes);
        AttributeConverterSet {
            inner,
            allow_unknown_attributes,
        }
    }

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
