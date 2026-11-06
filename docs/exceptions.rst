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

   Identity-store error: an outcome of a NameID operation (no format could be
   determined, an unknown NameID, a rejected EPTID digest).

.. py:exception:: SamlStoreError

   A storage backend failed: an outage, never "no record". Raised by
   :class:`~pygamlastan.idp.IdentDb`, :class:`~pygamlastan.idp.Eptid`,
   :class:`~pygamlastan.idp.InMemoryAssertionStore` and the response engine when
   the backend cannot answer, and also when a Python backend returns a record
   that is not the caller's (see :class:`~pygamlastan.idp.IdentityStore`).

   It is a direct child of :class:`SamlError`, **not** of
   :class:`SamlIdentError`. Code that wraps identity calls in
   ``except SamlIdentError: principal = None`` therefore does not turn a
   database outage into "no such principal"; catch ``SamlStoreError`` to handle
   an outage on purpose.

.. py:exception:: StoreConformanceError

   An :class:`~pygamlastan.idp.IdentityStore` backend failed a check of
   :func:`pygamlastan.idp.check_store_conformance`. The failing check is in
   ``.check`` and what it found in ``.message``.

.. py:exception:: NameIdValueTaken

   Raised by a Python :class:`~pygamlastan.idp.IdentityStore` to report that a
   NameID value is already used by another user's record. A
   :class:`SamlIdentError`.

.. py:exception:: NameIdDurableExists

   Raised by a Python :class:`~pygamlastan.idp.IdentityStore` to report that the
   user already has a durable NameID of this format for the same
   ``(SPNameQualifier, NameQualifier)``. A :class:`SamlIdentError`.

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
