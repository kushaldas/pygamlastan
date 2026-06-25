Identity Provider integration
=============================

An Identity Provider (IdP) receives an ``AuthnRequest`` from an SP, authenticates
the user, and returns a ``Response`` carrying an assertion.

Processing an incoming AuthnRequest
-----------------------------------

Parse the request, then distil it into the fields you need with
:func:`pygamlastan.profiles.process_authn_request`:

.. code-block:: python

   from pygamlastan import xml, profiles

   request = xml.parse_authn_request(request_xml)
   processed = profiles.process_authn_request(request)

   processed.request_id               # echo as InResponseTo
   processed.sp_entity_id             # who is asking
   processed.acs_url                  # where to send the response
   processed.acs_binding              # which binding to use
   processed.requested_name_id_format # the SP's preferred NameID format
   processed.force_authn              # must the user re-authenticate?

If you have the SP's metadata, pass it so the ACS URL/binding can be validated
against the registered endpoints:

.. code-block:: python

   from pygamlastan import metadata

   sp_md = metadata.parse_entity(sp_metadata_xml)
   processed = profiles.process_authn_request(request, sp_metadata=sp_md)

Building the response
---------------------

After you authenticate the user, describe the response with
:class:`pygamlastan.profiles.ResponseOptions` and build it with
:func:`pygamlastan.profiles.create_response`:

.. code-block:: python

   from pygamlastan import core, profiles

   options = profiles.ResponseOptions(
       idp_entity_id="https://idp.example.org",
       sp_entity_id=processed.sp_entity_id,
       acs_url=processed.acs_url,
       in_response_to=processed.request_id,
       assertion_lifetime_seconds=300,
       session_index="session-42",                 # for later Single Logout
       authn_context_class_ref=core.AUTHN_CONTEXT_PASSWORD,
       attributes=[
           core.Attribute("mail", values=["alice@example.org"]),
           core.Attribute("displayName", values=["Alice"]),
       ],
   )
   name_id = core.NameId(
       "alice@example.org",
       format=processed.requested_name_id_format or core.NAMEID_TRANSIENT,
   )
   response = profiles.create_response(options, name_id)

Then sign it (see :doc:`signing`) and deliver it via the chosen binding (see
:doc:`bindings`).

IdP-initiated (unsolicited) responses
-------------------------------------

When there is no prior request, use
:func:`pygamlastan.profiles.create_unsolicited_response`. The resulting message
has no ``InResponseTo``:

.. code-block:: python

   response = profiles.create_unsolicited_response(
       "https://idp.example.org",
       "https://sp.example.org/sp",
       "https://sp.example.org/acs",
       core.NameId("alice", format=core.NAMEID_TRANSIENT),
       attributes=[core.Attribute("mail", values=["alice@example.org"])],
       authn_context_class_ref=core.AUTHN_CONTEXT_PASSWORD,
   )

Targeted identifiers and the authn broker
-----------------------------------------

The :doc:`../api/idp` module provides IdP building blocks:

* :class:`pygamlastan.idp.Eptid` derives a stable, per-SP eduPersonTargetedID so
  the same user is unlinkable across different SPs.
* :class:`pygamlastan.idp.AuthnBroker` registers authentication methods and
  selects one for a requested authentication context.
* :class:`pygamlastan.idp.InMemoryAssertionStore` retains issued assertions to
  answer later queries.

.. code-block:: python

   from pygamlastan import idp

   eptid = idp.Eptid("server-side-secret")
   name_id = eptid.name_id("https://idp.example.org", processed.sp_entity_id, "user-123")
