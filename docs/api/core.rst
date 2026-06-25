pygamlastan.core
================

.. py:module:: pygamlastan.core

Owned SAML 2.0 types plus the protocol constants and namespace URIs. Objects in
this module wrap an owned gamlastan value; getters return plain Python values or
further wrapped objects. The build-side types (:class:`NameId`,
:class:`Issuer`, :class:`Attribute`) have constructors; the rest are produced by
parsing (see :doc:`xml`) or by the profiles.

Functions
---------

.. py:function:: generate_id() -> str

   Generate a fresh, random SAML id (an XML ``NCName``, with a leading
   underscore) suitable for message and assertion ids.

.. py:function:: validate_entity_id(value: str) -> str

   Validate an entity id (non-empty, within length limits) and return it.
   Raises :class:`pygamlastan.SamlCoreError` on an invalid value.

Build-side types
----------------

.. py:class:: NameId(value, format=None, name_qualifier=None, sp_name_qualifier=None, sp_provided_id=None)

   A SAML ``<NameID>``.

   .. py:attribute:: value
      :type: str
   .. py:attribute:: format
      :type: str | None
   .. py:attribute:: name_qualifier
      :type: str | None
   .. py:attribute:: sp_name_qualifier
      :type: str | None
   .. py:attribute:: sp_provided_id
      :type: str | None

.. py:class:: Issuer(value, format=None, name_qualifier=None, sp_name_qualifier=None)

   A SAML ``<Issuer>``. Exposes ``value``, ``format``, ``name_qualifier`` and
   ``sp_name_qualifier``.

.. py:class:: Attribute(name, values=None, name_format=None, friendly_name=None)

   A SAML ``<Attribute>``. ``values`` is a list of strings on construction.

   .. py:attribute:: name
      :type: str
   .. py:attribute:: name_format
      :type: str | None
   .. py:attribute:: friendly_name
      :type: str | None
   .. py:attribute:: values

      All values as native Python objects (str / int / bool / bytes /
      :class:`NameId`).

   .. py:attribute:: string_values
      :type: list[str]

      Only the string-typed values, for convenience.

.. py:class:: NameIdPolicy(format=None, sp_name_qualifier=None, allow_create=True)

   A ``<NameIDPolicy>``. Exposes ``format``, ``sp_name_qualifier`` and
   ``allow_create``.

Parsed types
------------

These are returned by parsing and by the profiles; their attributes are
read-only.

.. py:class:: Assertion

   ``id``, ``issue_instant``, ``issuer`` (:class:`Issuer`), ``has_signature``,
   ``subject`` (:class:`Subject` | None), ``conditions`` (:class:`Conditions` |
   None), ``authn_statements`` (list of :class:`AuthnStatement`),
   ``attribute_statements`` (list of :class:`AttributeStatement`).

.. py:class:: Response

   ``id``, ``issue_instant``, ``destination``, ``in_response_to``, ``issuer``,
   ``has_signature``, ``status`` (:class:`Status`), ``assertions`` (list of
   :class:`Assertion`), ``encrypted_assertion_count``.

   .. py:method:: is_success() -> bool
   .. py:method:: to_xml() -> str

.. py:class:: AuthnRequest

   ``id``, ``issue_instant``, ``destination``, ``issuer``, ``has_signature``,
   ``name_id_policy`` (:class:`NameIdPolicy` | None), ``requested_authn_context``
   (:class:`RequestedAuthnContext` | None), ``scoping`` (:class:`Scoping` |
   None), ``force_authn``, ``is_passive``, ``assertion_consumer_service_url``,
   ``protocol_binding``, ``provider_name``.

   .. py:method:: to_xml() -> str

.. py:class:: Subject

   ``name_id`` (:class:`NameId` | None; ``None`` for an encrypted id) and
   ``subject_confirmations`` (list of :class:`SubjectConfirmation`).

.. py:class:: SubjectConfirmation

   ``method``, ``name_id``, ``subject_confirmation_data``
   (:class:`SubjectConfirmationData` | None).

.. py:class:: SubjectConfirmationData

   ``not_before``, ``not_on_or_after`` (aware :class:`datetime.datetime` | None),
   ``recipient``, ``in_response_to``, ``address``.

.. py:class:: Conditions

   ``not_before``, ``not_on_or_after``, ``one_time_use``,
   ``audience_restrictions`` (list of :class:`AudienceRestriction`),
   ``proxy_restriction`` (:class:`ProxyRestriction` | None).

.. py:class:: AudienceRestriction

   ``audiences`` (list of str). :py:meth:`matches(entity_id) -> bool`.

.. py:class:: ProxyRestriction

   ``count`` (int | None), ``audiences`` (list of str).

.. py:class:: AuthnStatement

   ``authn_instant``, ``session_index``, ``session_not_on_or_after``,
   ``subject_locality`` (:class:`SubjectLocality` | None), ``authn_context``
   (:class:`AuthnContext`).

.. py:class:: AuthnContext

   ``authn_context_class_ref``, ``authn_context_decl_ref``,
   ``authenticating_authorities`` (list of str).

.. py:class:: SubjectLocality

   ``address``, ``dns_name``.

.. py:class:: AttributeStatement

   ``attributes`` (list of :class:`Attribute`).

.. py:class:: Status

   ``status_code`` (:class:`StatusCode`), ``status_message``, ``status_detail``.
   :py:meth:`is_success() -> bool`.

.. py:class:: StatusCode

   ``value``, ``sub_status`` (:class:`StatusCode` | None).
   :py:meth:`is_success() -> bool`.

.. py:class:: RequestedAuthnContext

   ``authn_context_class_refs`` (list of str), ``comparison`` (str).

.. py:class:: Scoping

   ``proxy_count``, ``idp_list`` (list of str), ``requester_ids`` (list of str).

.. py:class:: LogoutRequest

   ``id``, ``issue_instant``, ``destination``, ``issuer``, ``reason``,
   ``name_id`` (:class:`NameId` | None), ``session_indexes`` (list of str).
   :py:meth:`to_xml() -> str`.

.. py:class:: LogoutResponse

   ``id``, ``in_response_to``, ``issuer``, ``status``. :py:meth:`is_success`,
   :py:meth:`to_xml`.

Constants
---------

Module-level string constants mirror the SAML 2.0 specification.

**Bindings**: ``BINDING_HTTP_REDIRECT``, ``BINDING_HTTP_POST``,
``BINDING_HTTP_ARTIFACT``, ``BINDING_SOAP``, ``BINDING_PAOS``, ``BINDING_URI``.

**NameID formats**: ``NAMEID_TRANSIENT``, ``NAMEID_PERSISTENT``,
``NAMEID_EMAIL``, ``NAMEID_UNSPECIFIED``, ``NAMEID_ENTITY``, ``NAMEID_X509``,
``NAMEID_WINDOWS``, ``NAMEID_KERBEROS``, ``NAMEID_ENCRYPTED``.

**Subject confirmation**: ``CM_BEARER``, ``CM_HOLDER_OF_KEY``,
``CM_SENDER_VOUCHES``.

**Status codes**: ``STATUS_SUCCESS``, ``STATUS_REQUESTER``, ``STATUS_RESPONDER``,
``STATUS_VERSION_MISMATCH``, ``STATUS_AUTHN_FAILED``, ``STATUS_NO_AUTHN_CONTEXT``,
``STATUS_REQUEST_DENIED``, ``STATUS_UNKNOWN_PRINCIPAL``.

**Authentication context classes**: ``AUTHN_CONTEXT_PASSWORD``,
``AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT``, ``AUTHN_CONTEXT_X509``,
``AUTHN_CONTEXT_KERBEROS``, ``AUTHN_CONTEXT_UNSPECIFIED``.

**Attribute name formats**: ``ATTRNAME_FORMAT_URI``, ``ATTRNAME_FORMAT_BASIC``,
``ATTRNAME_FORMAT_UNSPECIFIED``.

**Namespaces**: ``SAML_ASSERTION_NS``, ``SAML_PROTOCOL_NS``,
``SAML_METADATA_NS``, ``XMLDSIG_NS``, ``XMLENC_NS``.
