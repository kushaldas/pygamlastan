//! Shared helpers for the binding: submodule creation and registration.

use pyo3::exceptions::PyUserWarning;
use pyo3::prelude::*;
use pyo3::types::PyModule;

/// Emit a Python `UserWarning` from Rust on a best-effort basis (it never raises
/// back into Rust). Used to flag security downgrades - permissive configs and
/// verification-weakening knobs - so they cannot be turned on silently.
pub fn warn(py: Python<'_>, message: &str) {
    if let Ok(warnings) = py.import("warnings") {
        let category = py.get_type::<PyUserWarning>();
        let _ = warnings.call_method1("warn", (message, category));
    }
}

/// Create a child submodule, register it under the parent, and insert it into
/// `sys.modules` as `pygamlastan.<name>` so both `import pygamlastan.<name>` and
/// attribute access work.
pub fn new_submodule<'py>(
    py: Python<'py>,
    parent: &Bound<'py, PyModule>,
    name: &str,
) -> PyResult<Bound<'py, PyModule>> {
    let child = PyModule::new(py, name)?;
    let qualified = format!("pygamlastan.{name}");
    child.setattr("__name__", &qualified)?;
    parent.add(name, &child)?;
    py.import("sys")?
        .getattr("modules")?
        .set_item(&qualified, &child)?;
    Ok(child)
}
