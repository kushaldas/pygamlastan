pygamlastan.metadata
====================

.. py:module:: pygamlastan.metadata

Parse and inspect SAML metadata. See the :doc:`../guides/metadata` guide. Errors
raise :class:`pygamlastan.SamlMetadataError` (or
:class:`pygamlastan.SamlXmlError` for malformed XML).

.. note::

   Remote and published metadata is attacker-influenced, so :func:`parse_entity`
   and :func:`parse_entities` parse through the same hardened path as the
   :doc:`xml` module: DTD/``<!DOCTYPE>`` documents are rejected and uppsala's
   resource limits bound entity-expansion and nesting amplification. See
   :ref:`xml-hardening`.

.. py:function:: parse_entity(xml: str) -> EntityDescriptor

   Parse a single ``<md:EntityDescriptor>`` document.

.. py:function:: parse_entities(xml: str) -> list[EntityDescriptor]

   Parse a ``<md:EntitiesDescriptor>`` aggregate into its child entities.

.. py:function:: validate_entity(entity: EntityDescriptor) -> None

   Validate an entity against basic metadata requirements.

.. py:class:: EntityDescriptor

   .. py:attribute:: entity_id
      :type: str
   .. py:attribute:: valid_until
   .. py:attribute:: has_signature
      :type: bool
   .. py:method:: is_idp() -> bool
   .. py:method:: is_sp() -> bool
   .. py:method:: single_sign_on_services() -> list[EndpointInfo]

      IdP SingleSignOnService endpoints.

   .. py:method:: assertion_consumer_services() -> list[EndpointInfo]

      SP AssertionConsumerService endpoints (indexed).

   .. py:method:: single_logout_services(role: str = "idp") -> list[EndpointInfo]
   .. py:method:: name_id_formats(role: str = "idp") -> list[str]
   .. py:method:: signing_certificates(role: str = "idp") -> list[bytes]

      DER X.509 signing certificates for the role.

   .. py:method:: encryption_certificates(role: str = "sp") -> list[bytes]

   .. py:attribute:: registration_authority
      :type: str | None

      ``mdrpi:RegistrationInfo/@registrationAuthority`` - the federation operator
      that registered this entity (used to select a release policy).

   .. py:method:: entity_categories() -> list[str]

      The published entity-category URIs (``mdattr:EntityAttributes``,
      ``http://macedir.org/entity-category``).

   .. py:method:: entity_attribute_values(name: str) -> list[str]

      All values of a named entity attribute (e.g.
      ``urn:oasis:names:tc:SAML:profiles:subject-id:req``).

   .. py:method:: entity_attributes() -> list[tuple[str, list[str]]]

      Every entity attribute as ``(name, values)`` pairs.

   .. py:method:: supported_algorithms() -> list[str]

      Algorithm URIs from ``alg:SigningMethod`` / ``alg:DigestMethod``, across
      the entity and its SSO roles, de-duplicated in document order.

   .. py:method:: ui_info(role: str = "sp") -> UiInfo | None

      The ``mdui:UIInfo`` (display name / logo / description) for the role
      (``"sp"`` or ``"idp"``), if published.

      .. important::

         The returned strings and URLs are **attacker-controlled** metadata.
         HTML-escape display names / descriptions / keywords before rendering
         (stored-XSS risk) and allowlist URL/logo schemes (typically ``https:``)
         before using them as ``href`` / ``<img src>`` - the URLs are **not**
         scheme-checked and may be ``javascript:`` or hostile ``data:`` URIs. See
         :doc:`the security guide <../guides/security>`.

   .. py:method:: requested_attributes(acs_index: int | None = None) -> tuple[list[pygamlastan.core.Attribute], list[pygamlastan.core.Attribute]]

      The SP's ``(required, optional)`` requested attributes from its
      ``AttributeConsumingService`` (the one at ``acs_index``, else the default).
      Feed these straight into :py:meth:`pygamlastan.idp.ReleasePolicy.filter`.

   .. py:method:: to_xml() -> str

.. py:class:: UiInfo

   Parsed ``mdui:UIInfo``. The localized fields are lists of ``(lang, value)``
   tuples (``lang`` may be ``None``): ``display_names``, ``descriptions``,
   ``information_urls``, ``privacy_statement_urls``, ``keywords``. ``logos`` is a
   list of :py:class:`UiLogo`.

   .. warning::

      Every field is copied **verbatim from attacker-controllable metadata** and
      is parsed for display, not validated for safety. Output-encode the text
      fields (``display_names`` / ``descriptions`` / ``keywords``) to avoid
      stored XSS, and scheme-allowlist the URL fields (``information_urls`` /
      ``privacy_statement_urls``) before using them as links.

.. py:class:: UiLogo

   An ``mdui:Logo``: ``url`` (str), ``width`` / ``height`` (int | None), ``lang``
   (str | None).

   .. warning::

      ``url`` is **attacker-controlled and unvalidated** - its scheme is not
      restricted, so it may be ``javascript:`` or a hostile ``data:`` URI. Reject
      anything outside an expected allowlist (typically ``https:``, plus ``data:``
      only when intentionally inlining images) before using it as ``<img src>``.

.. py:class:: EndpointInfo

   A resolved endpoint.

   .. py:attribute:: binding
      :type: str
   .. py:attribute:: location
      :type: str
   .. py:attribute:: response_location
      :type: str | None
   .. py:attribute:: index
      :type: int | None
   .. py:attribute:: is_default
      :type: bool | None
