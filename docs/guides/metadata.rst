Metadata
========

The :doc:`../api/metadata` module parses SAML metadata into an
:class:`~pygamlastan.metadata.EntityDescriptor`, exposes its endpoints and keys,
and serializes it back to XML.

Parsing
-------

.. code-block:: python

   from pygamlastan import metadata

   ed = metadata.parse_entity(metadata_xml)
   ed.entity_id          # "https://idp.example.org"
   ed.is_idp(), ed.is_sp()

Parse an aggregate (``<md:EntitiesDescriptor>``) into a list of entities:

.. code-block:: python

   for ed in metadata.parse_entities(federation_xml):
       print(ed.entity_id)

Endpoints
---------

Endpoint accessors take a ``role`` of ``"idp"`` or ``"sp"`` where ambiguous and
return :class:`~pygamlastan.metadata.EndpointInfo` objects:

.. code-block:: python

   for ep in ed.single_sign_on_services():           # IdP SSO endpoints
       print(ep.binding, ep.location)

   for ep in ed.assertion_consumer_services():       # SP ACS endpoints (indexed)
       print(ep.index, ep.is_default, ep.binding, ep.location)

   ed.single_logout_services(role="idp")
   ed.name_id_formats(role="idp")

Keys
----

Signing and encryption certificates are returned as DER bytes. A
``KeyDescriptor`` without an explicit ``use`` is valid for both, so it appears in
both lists:

.. code-block:: python

   signing_certs = ed.signing_certificates(role="idp")        # list[bytes] (DER)
   encryption_certs = ed.encryption_certificates(role="sp")

   # Feed a signing cert straight into a verifier:
   from pygamlastan import crypto
   verifier = crypto.SamlVerifier.from_cert(signing_certs[0])

Validation and serialization
----------------------------

.. code-block:: python

   metadata.validate_entity(ed)     # raises SamlMetadataError if non-conformant
   xml = ed.to_xml()                # round-trip back to metadata XML
