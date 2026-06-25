"""pygamlastan - Python bindings for the gamlastan SAML 2.0 library.

The compiled extension is `pygamlastan._native`. Importing it registers each
gamlastan area as a submodule in `sys.modules` (`pygamlastan.core`, etc.); this
package re-exports the native names and submodules so the public API is the same
whether you `import pygamlastan` or `from pygamlastan import profiles`.
"""

from ._native import (  # noqa: F401
    __version__,
    SamlError,
    SamlCoreError,
    SamlXmlError,
    SamlCryptoError,
    SamlBindingError,
    SamlMetadataError,
    SamlSecurityError,
    SamlProfileError,
    SamlPolicyError,
    SamlIdentError,
    attribute_map,
    bindings,
    core,
    crypto,
    idp,
    metadata,
    profiles,
    security,
    xml,
)

__all__ = [
    "__version__",
    "SamlError",
    "SamlCoreError",
    "SamlXmlError",
    "SamlCryptoError",
    "SamlBindingError",
    "SamlMetadataError",
    "SamlSecurityError",
    "SamlProfileError",
    "SamlPolicyError",
    "SamlIdentError",
    "core",
    "xml",
    "crypto",
    "bindings",
    "metadata",
    "security",
    "profiles",
    "attribute_map",
    "idp",
]
