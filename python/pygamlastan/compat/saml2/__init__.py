"""A ``pysaml2``-compatible facade over pygamlastan.

This package mirrors the slice of the ``saml2`` module layout that an eduID-style
SP consumes (``client``, ``config``, ``ident``, ``response``, ``saml``,
``cache``, ``metadata``, ``s_utils``, ``sigver``, ``server``). Only the SP flow
is implemented today; the IdP ``server`` module is a Phase 2 placeholder.

The binding constants are the SAML 2.0 binding URIs - identical values to the
real ``saml2`` package, so config dicts and call sites that compare against them
keep working unchanged.
"""

from pygamlastan.core import (
    BINDING_HTTP_ARTIFACT,
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    BINDING_PAOS,
    BINDING_SOAP,
    BINDING_URI,
)

__all__ = [
    "BINDING_HTTP_ARTIFACT",
    "BINDING_HTTP_POST",
    "BINDING_HTTP_REDIRECT",
    "BINDING_PAOS",
    "BINDING_SOAP",
    "BINDING_URI",
]
