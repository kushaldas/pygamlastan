Attribute mapping
=================

SAML carries attributes by their wire name (often an OID or URN), while
applications prefer friendly local names like ``mail`` or ``displayName``. The
:doc:`../api/attribute_map` module converts between the two using the maps
shipped with gamlastan (``saml_uri``, ``basic``, ``shibboleth_uri``,
``adfs_v1x``, ``adfs_v20``).

Converting received attributes to local names
---------------------------------------------

.. code-block:: python

   from pygamlastan import attribute_map

   converters = attribute_map.AttributeConverterSet.with_default_maps(
       allow_unknown_attributes=True,   # pass through names with no mapping
   )

   # `attributes` is e.g. AuthnResult.attributes (list[core.Attribute]).
   local = converters.to_local(attributes)
   for la in local:
       print(la.name, la.values)        # "mail" ["alice@example.org"]

Converting local attributes back to the wire
--------------------------------------------

.. code-block:: python

   from pygamlastan import core

   wire = converters.from_local(local, core.ATTRNAME_FORMAT_URI)
   # wire is list[core.Attribute] with OID/URN names, ready for a Response.

A single map
------------

When you only need one format, use a single
:class:`~pygamlastan.attribute_map.AttributeConverter`:

.. code-block:: python

   conv = attribute_map.AttributeConverter.from_static("saml_uri")
   conv.to_local_name("urn:oid:0.9.2342.19200300.100.1.3")   # "mail"
   conv.to_wire_name("mail")                                  # the OID

eduPersonTargetedID
-------------------

EPTID values are NameID-valued attributes. Pack and unpack them with the
module-level helpers:

.. code-block:: python

   nid = core.NameId("opaque-id", format=core.NAMEID_PERSISTENT)
   attr = attribute_map.eptid_attribute([nid])     # name == attribute_map.EPTID_OID
   ids = attribute_map.eptid_name_ids(attr)         # back to [core.NameId]
