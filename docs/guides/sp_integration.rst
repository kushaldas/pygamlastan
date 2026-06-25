Service Provider integration
============================

A Service Provider (SP) sends an ``AuthnRequest`` to an Identity Provider (IdP)
and later receives and validates a ``Response``. This guide covers both steps.

Resolving the IdP's metadata
----------------------------

Before it can talk to an IdP, the SP needs that IdP's metadata: the SSO endpoint
to send the ``AuthnRequest`` to, and the signing certificate to verify the
``Response`` with. As on the IdP side there is no provider database in the
binding; you resolve the IdP's ``entityID`` to its metadata and read what you
need from it:

.. code-block:: python

   from pygamlastan import metadata

   ed = metadata.parse_entity(idp_metadata_xml)
   sso = ed.single_sign_on_services()[0].location   # AuthnRequest destination
   idp_signing_certs = ed.signing_certificates(role="idp")   # list[bytes] (DER)

The two sources mirror the IdP side and differ in how trust is established:

**Local files (trusted as provided).** Self-contained IdP metadata XML on disk,
trusted as-is. A file may be a single ``<md:EntityDescriptor>`` or a
whole-federation aggregate; :func:`~pygamlastan.metadata.parse_entities` indexes
every entity in an aggregate, so one federation file gives you every IdP in it.

**MDQ (signature-verified per entity).** Fetch the IdP on demand by ``entityID``
and signature-verify it against the federation signing certificate before trust:

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

   The MDQ base URL is the service root, **not** an aggregate-file directory, and
   the signing certificate must match the federation **environment**. For SWAMID
   QA the base is ``https://mds.swamid.se/qa/`` (a lookup hits
   ``.../qa/entities/<id>``) and the signer is the QA cert
   (``https://mds.swamid.se/qa/md/swamid-qa.crt``); ``https://mds.swamid.se/qa/md/``
   serves only aggregate files (no ``/entities/`` endpoint, every lookup ``404``)
   and production uses a different signer. See
   :doc:`idp_integration` for the full discussion.

The signing certificate(s) you read from the resolved IdP metadata are exactly
what you feed to :class:`~pygamlastan.crypto.SamlVerifier` in
:ref:`Processing the response <processing-the-response>` below.

Building an AuthnRequest
------------------------

Describe the request with :class:`pygamlastan.profiles.AuthnRequestOptions`, then
call :func:`pygamlastan.profiles.create_authn_request`:

.. code-block:: python

   from pygamlastan import core, profiles

   options = profiles.AuthnRequestOptions(
       sp_entity_id="https://sp.example.org/sp",
       acs_url="https://sp.example.org/acs",
       destination="https://idp.example.org/sso",   # IdP SSO endpoint
       protocol_binding=core.BINDING_HTTP_POST,      # how the IdP should reply
       name_id_format=core.NAMEID_TRANSIENT,
       force_authn=True,
       authn_context_class_refs=[core.AUTHN_CONTEXT_PASSWORD],
       authn_context_comparison="exact",
   )
   request = profiles.create_authn_request(options)
   xml = request.to_xml()

Every option maps to a field on the resulting message; for example
``request.issuer.value`` is the SP entity id and
``request.requested_authn_context.comparison`` is ``"exact"``.

Sending the request
-------------------

Encode the request for the wire with the :doc:`bindings <bindings>`. For the
HTTP-Redirect binding:

.. code-block:: python

   from pygamlastan import bindings

   redirect_url = bindings.redirect_encode(
       xml.encode(), is_request=True,
       destination="https://idp.example.org/sso",
       relay_state="opaque-state",
   )
   # return an HTTP 302 to redirect_url

Store ``request.id`` in your session: you will pass it as ``expected_request_id``
when the response comes back, which binds the response to this request.

.. _processing-the-response:

Processing the response
-----------------------

When the IdP posts the ``Response`` back to your ACS:

.. code-block:: python

   from pygamlastan import xml, crypto, security, profiles

   # 1. Cryptographically verify the signature with the IdP's signing cert
   #    (idp_signing_certs[0] from the resolved IdP metadata above).
   verifier = crypto.SamlVerifier.from_cert(idp_certificate_pem)
   verified = verifier.verify_enveloped(response_xml)

   # 2. Parse.
   response = xml.parse_response(response_xml)

   # 3. Validate and extract the identity.
   result = profiles.process_response(
       response,
       security.SecurityConfig(),
       sp_entity_id="https://sp.example.org/sp",
       acs_url="https://sp.example.org/acs",
       expected_idp_entity_id="https://idp.example.org",
       expected_request_id=session["request_id"],
       verified_signed_ids=verified.signed_reference_ids(),
       replay_cache=replay_cache,   # see the validation guide
   )

On success you get an :class:`pygamlastan.profiles.AuthnResult`:

.. code-block:: python

   result.name_id                 # the subject identifier
   result.name_id_format          # its format URI, if any
   result.session_index           # needed later for Single Logout
   result.authn_context_class_ref # how the user authenticated
   result.idp_entity_id           # the issuing IdP
   result.attributes              # list[core.Attribute]
   result.attributes_dict()       # {name: [values]} for convenience

Why pass ``verified_signed_ids``?
---------------------------------

The presence of a ``<Signature>`` element proves nothing on its own. By passing
the reference ids returned from a *trusted* :class:`~pygamlastan.crypto.SamlVerifier`,
you tell the profile which assertion/response ids were actually verified against
the IdP's key, so the "assertions must be signed" requirement is bound to real
cryptography rather than to markup. See :doc:`signing` and :doc:`validation`.
