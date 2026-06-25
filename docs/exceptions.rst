Exceptions
==========

.. py:module:: pygamlastan
   :no-index:

All errors raised by pygamlastan derive from a single base class, so you can
catch one base type or a specific subtype. Operations raise these on failure;
note that security validation via
:func:`pygamlastan.security.validate_response` instead returns a structured
:class:`~pygamlastan.security.ValidationResult` (it does not raise), while
:func:`pygamlastan.profiles.process_response` raises
:class:`SamlProfileError` on the first failure.

.. py:exception:: SamlError

   Base class for every pygamlastan error.

.. py:exception:: SamlCoreError

   Invalid core SAML value (e.g. a malformed entity id).

.. py:exception:: SamlXmlError

   XML parsing or serialization failure.

.. py:exception:: SamlCryptoError

   Signing, verification, encryption, decryption, or canonicalization failure.

.. py:exception:: SamlBindingError

   Protocol-binding encode/decode failure (bad base64, oversized RelayState,
   invalid artifact, ...).

.. py:exception:: SamlMetadataError

   Metadata validation failure.

.. py:exception:: SamlSecurityError

   Security validation error surfaced as an exception.

.. py:exception:: SamlProfileError

   A profile operation failed, including assertion/response validation in
   :func:`pygamlastan.profiles.process_response`.

.. py:exception:: SamlPolicyError

   Attribute-release policy error.

.. py:exception:: SamlIdentError

   Identity-store error.

Example
-------

.. code-block:: python

   import pygamlastan
   from pygamlastan import xml

   try:
       response = xml.parse_response(untrusted_xml)
   except pygamlastan.SamlXmlError as exc:
       ...                      # malformed XML
   except pygamlastan.SamlError as exc:
       ...                      # any other pygamlastan error
