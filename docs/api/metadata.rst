pygamlastan.metadata
====================

.. py:module:: pygamlastan.metadata

Parse and inspect SAML metadata. See the :doc:`../guides/metadata` guide. Errors
raise :class:`pygamlastan.SamlMetadataError` (or
:class:`pygamlastan.SamlXmlError` for malformed XML).

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
   .. py:method:: to_xml() -> str

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
