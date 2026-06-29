"""Compatibility shims that expose pygamlastan behind the API of other SAML
libraries, so existing code can migrate with minimal churn.

Currently provides :mod:`pygamlastan.compat.saml2`, a drop-in subset of the
``pysaml2`` API surface (the SP-side flow: AuthnRequest creation, response
processing, Single Logout, metadata and the NameID code/decode helpers) backed
entirely by pygamlastan. Swap ``from saml2 import X`` for
``from pygamlastan.compat.saml2 import X``.
"""
