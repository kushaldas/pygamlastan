pygamlastan.attribute_map
=========================

.. py:module:: pygamlastan.attribute_map

Convert between wire attribute names (OIDs/URNs) and friendly local names using
the shipped maps. See the :doc:`../guides/attributes` guide.

.. py:data:: EPTID_OID
   :type: str

   The OID name for eduPersonTargetedID.

.. py:class:: AttributeConverterSet(converters: list[AttributeConverter], allow_unknown_attributes: bool = False)

   A set of converters covering multiple name formats. Build one from your own
   converters, for example maps loaded from a pysaml2 ``attribute_map_dir``; the
   converters are copied in, so later changes to them are not seen. Pass it to
   :class:`pygamlastan.idp.ReleasePolicy` (``converters=...``) so entity
   categories, requested attributes and restrictions resolve names through it.

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

   .. py:staticmethod:: from_directions(name_format: str, fro: list[tuple[str, str]] | None = None, to: list[tuple[str, str]] | None = None) -> AttributeConverter

      Build from independent inbound and outbound maps, the shape of a pysaml2
      attribute map (``MAP["fro"]`` and ``MAP["to"]``). ``fro`` holds
      ``(wire name, local name)`` pairs and ``to`` holds
      ``(local name, wire name)`` pairs. A key that repeats within one direction
      keeps its later entry.

      Use this, not :meth:`add_mapping`, for a map whose two directions differ.
      Real maps do: one production ``saml_uri`` map has 83 inbound and 99 outbound
      entries, with 13 local names that can be sent but are not recognised on
      the way in. Mirroring such a map would make an SP-supplied attribute name
      resolve to a local attribute it did not before (which feeds release
      matching), and where several wire names share a local name it would make
      the outbound name depend on insertion order.

   .. py:method:: add_mapping(wire: str, local: str) -> None

      Add one entry in both directions. Only for a map that really is symmetric.

   .. py:method:: add_wire_to_local(wire: str, local: str) -> None

      Add one inbound entry. The reverse is not added, so ``local`` is not sent
      as ``wire`` unless an outbound entry says so.

   .. py:method:: add_local_to_wire(local: str, wire: str) -> None

      Add one outbound entry. The reverse is not added, so a received ``wire``
      is not recognised as ``local`` unless an inbound entry says so.
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
