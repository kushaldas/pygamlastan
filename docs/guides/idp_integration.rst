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

Resolving the SP's metadata
---------------------------

To validate the request (above) and to know where to send the response, the IdP
needs the requesting SP's metadata. There is no SP database baked into the
binding; you resolve the SP's ``entityID`` to its metadata yourself. Two sources
are common, and they differ in *how trust is established*:

**Local files (trusted as provided).** Self-contained SP metadata XML kept on
disk. Because you placed the file there, it is trusted as-is and is not
re-verified against a federation signing cert. A file may be a single
``<md:EntityDescriptor>`` or a whole-federation aggregate
(``<md:EntitiesDescriptor>``); :func:`~pygamlastan.metadata.parse_entities`
indexes every entity in an aggregate, so dropping one federation file gives you
every SP in it.

**MDQ, the Metadata Query Protocol (signature-verified per entity).** An SP is
fetched on demand by ``entityID`` and **must** be signature-verified against the
federation's signing certificate before you trust it:

.. code-block:: python

   import urllib.parse, urllib.request
   from pygamlastan import crypto

   def mdq_fetch(base_url: str, entity_id: str, signer_cert: bytes) -> str | None:
       # MDQ single-entity request: {base}/entities/{url-encoded entityID}
       url = f"{base_url.rstrip('/')}/entities/{urllib.parse.quote(entity_id, safe='')}"
       req = urllib.request.Request(url, headers={"Accept": "application/samlmetadata+xml"})
       with urllib.request.urlopen(req, timeout=10) as resp:
           xml_text = resp.read().decode()
       # MANDATORY: reject metadata whose enveloped signature does not verify.
       verifier = crypto.SamlVerifier.from_cert(signer_cert)   # cert PEM/DER bytes
       if not verifier.verify_enveloped(xml_text).is_valid():
           return None
       return xml_text

.. warning::

   The MDQ base URL is the service root, **not** an aggregate-file directory.
   For SWAMID QA the base is ``https://mds.swamid.se/qa/`` (so a lookup hits
   ``https://mds.swamid.se/qa/entities/<id>``). ``https://mds.swamid.se/qa/md/``
   looks similar but only serves whole-federation aggregate files and has no
   ``/entities/`` endpoint, so every per-entity lookup there returns ``404``.

.. warning::

   The signing certificate you verify MDQ (and aggregate) metadata against must
   match the federation **environment**. SWAMID QA metadata is signed by the QA
   signer (``https://mds.swamid.se/qa/md/swamid-qa.crt``, CN *"Metadata Signer -
   SWAMID QA - 2023"*); the production federation uses a different signer
   (``https://mds.swamid.se/md/md-signer2.crt``). Verifying QA metadata against
   the production cert fails, and vice versa.

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

Releasing attributes
--------------------

The example above uses bare attribute names for brevity. Real federations
(SWAMID, eduGAIN, ...) expect eduPerson/SAML attributes carried with the **URI**
name-format, where the ``Name`` is an OID and a human-readable ``FriendlyName``
accompanies it:

.. code-block:: python

   from pygamlastan import core

   fmt = core.ATTRNAME_FORMAT_URI
   attributes = [
       core.Attribute("urn:oid:2.16.840.1.113730.3.1.241", values=[full_name],
                      friendly_name="displayName", name_format=fmt),
       core.Attribute("urn:oid:2.5.4.42", values=[first_name],
                      friendly_name="givenName", name_format=fmt),
       core.Attribute("urn:oid:2.5.4.4", values=[last_name],
                      friendly_name="sn", name_format=fmt),
       core.Attribute("urn:oid:0.9.2342.19200300.100.1.3", values=[email],
                      friendly_name="mail", name_format=fmt),
   ]

Common OIDs: ``displayName`` ``2.16.840.1.113730.3.1.241``, ``givenName``
``2.5.4.42``, ``sn`` ``2.5.4.4``, ``cn`` ``2.5.4.3``, ``mail``
``0.9.2342.19200300.100.1.3``, ``uid`` ``0.9.2342.19200300.100.1.1``,
``eduPersonPrincipalName`` ``1.3.6.1.4.1.5923.1.1.1.6``,
``eduPersonScopedAffiliation`` ``1.3.6.1.4.1.5923.1.1.1.9``,
``schacHomeOrganization`` ``1.3.6.1.4.1.25178.1.2.9``.

**Scoped attributes** (``eduPersonPrincipalName``,
``eduPersonScopedAffiliation``) carry a ``value@scope`` form, where ``scope`` is
the IdP's home-organization domain. Make the scope a deployment setting rather
than hard-coding it:

.. code-block:: python

   eppn = f"{username}@{scope}"            # scope e.g. "example.org"
   affiliation = f"member@{scope}"

If you let :doc:`attribute mapping <attributes>` build the wire attributes from
local names, :meth:`~pygamlastan.attribute_map.AttributeConverterSet.from_local`
applies the OID and URI format for you.

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

A complete worked example
-------------------------

``examples/django-idp/`` in the source tree is a self-contained Django SAML IdP
built on this binding, with Docker Compose + Caddy. It ties together everything
above: ``idp/sp_resolver.py`` resolves SPs from local files or MDQ (with the
mandatory signature check), and ``idp/saml_logic.py`` builds, attribute-fills,
and assertion-signs the response. Its ``.env`` configures the MDQ base, the
federation signer cert, and the home-organization scope used for scoped
attributes.
