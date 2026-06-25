pygamlastan.attribute_map
=========================

.. py:module:: pygamlastan.attribute_map

Convert between wire attribute names (OIDs/URNs) and friendly local names using
the shipped maps. See the :doc:`../guides/attributes` guide.

.. py:data:: EPTID_OID
   :type: str

   The OID name for eduPersonTargetedID.

.. py:class:: AttributeConverterSet

   A set of converters covering multiple name formats.

   .. py:staticmethod:: with_default_maps(allow_unknown_attributes: bool = False) -> AttributeConverterSet

      Preload all shipped default maps. With ``allow_unknown_attributes`` set,
      names that have no mapping pass through unchanged.

   .. py:method:: to_local(attributes: list[pygamlastan.core.Attribute]) -> list[LocalAttribute]
   .. py:method:: from_local(ava: list[LocalAttribute], name_format: str) -> list[pygamlastan.core.Attribute]
   .. py:method:: local_name(attribute: pygamlastan.core.Attribute) -> str | None

.. py:class:: AttributeConverter(name_format: str)

   A single-format converter.

   .. py:staticmethod:: from_static(name: str) -> AttributeConverter

      Build from a shipped map name: ``"saml_uri"``, ``"basic"``,
      ``"shibboleth_uri"``, ``"adfs_v1x"`` or ``"adfs_v20"``.

   .. py:method:: add_mapping(wire: str, local: str) -> None
   .. py:method:: to_local_name(wire_name: str) -> str | None
   .. py:method:: to_wire_name(local_name: str) -> str | None
   .. py:attribute:: name_format
      :type: str

.. py:class:: LocalAttribute(name: str, values: list[str])

   An attribute by its local name.

   .. py:attribute:: name
      :type: str
   .. py:attribute:: values
      :type: list[str]

.. py:function:: eptid_attribute(name_ids: list[pygamlastan.core.NameId]) -> pygamlastan.core.Attribute

   Build an eduPersonTargetedID attribute from NameIDs.

.. py:function:: eptid_name_ids(attribute: pygamlastan.core.Attribute) -> list[pygamlastan.core.NameId]

   Extract the NameIDs from an eduPersonTargetedID attribute.
