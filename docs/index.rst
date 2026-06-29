pygamlastan
===========

**pygamlastan** is a Python binding for `gamlastan
<https://github.com/kushaldas/gamlastan>`_ 0.6.0, a pure-Rust SAML 2.0 library.
It exposes gamlastan's types, XML parsing, cryptography (including PKCS#11/HSM
signing), metadata handling, protocol bindings, security validation, and the
Web Browser SSO profiles to Python.

.. important::

   SAML is a security protocol, and this binding hands attacker-controlled XML
   straight into authentication decisions. Before integrating, read the
   :doc:`security guide <guides/security>`: it covers the signature
   trust-coupling model, the safe ``process_response_verified`` entry point,
   XXE/DTD input hardening, authentication-freshness reporting, and the
   "unsafe"/``permissive`` footguns you must avoid.

The binding mirrors gamlastan's modules as Python submodules:

.. list-table::
   :header-rows: 1
   :widths: 22 78

   * - Submodule
     - Purpose
   * - :doc:`pygamlastan.core <api/core>`
     - Owned SAML 2.0 types (Assertion, Response, NameId, ...) and constants.
   * - :doc:`pygamlastan.xml <api/xml>`
     - Parse SAML XML into owned core objects.
   * - :doc:`pygamlastan.crypto <api/crypto>`
     - Sign, verify, encrypt, decrypt, canonicalize; file keys and PKCS#11.
   * - :doc:`pygamlastan.bindings <api/bindings>`
     - HTTP-Redirect / HTTP-POST / Artifact encode and decode.
   * - :doc:`pygamlastan.metadata <api/metadata>`
     - Parse and inspect SAML metadata; serialize it back.
   * - :doc:`pygamlastan.security <api/security>`
     - The validation suite, its configuration, and the replay cache.
   * - :doc:`pygamlastan.profiles <api/profiles>`
     - Web Browser SSO: build requests/responses, process them.
   * - :doc:`pygamlastan.attribute_map <api/attribute_map>`
     - Wire to local attribute-name conversion.
   * - :doc:`pygamlastan.idp <api/idp>`
     - IdP infrastructure: targeted IDs, authn broker, assertion store.
   * - :doc:`pygamlastan.logout <api/logout>`
     - Single Logout: SP orchestrator, response builders, request validation.

Design in one sentence: parsing converts gamlastan's zero-copy ``*Ref`` views to
*owned* values at the boundary, so the Python objects you hold never borrow from
a Rust document and are safe to keep, pass around, and store.

.. toctree::
   :maxdepth: 2
   :caption: Getting started

   installation
   quickstart

.. toctree::
   :maxdepth: 2
   :caption: Guides

   guides/security
   guides/sp_integration
   guides/pysaml2_compat
   guides/idp_integration
   guides/signing
   guides/bindings
   guides/metadata
   guides/attributes
   guides/validation
   guides/writing_profiles
   guides/profile_worked_example

.. toctree::
   :maxdepth: 2
   :caption: API reference

   api/core
   api/xml
   api/crypto
   api/bindings
   api/metadata
   api/security
   api/profiles
   api/attribute_map
   api/idp
   api/logout

.. toctree::
   :maxdepth: 1
   :caption: Reference

   exceptions

Indices
-------

* :ref:`genindex`
* :ref:`search`
