Service Provider integration
============================

A Service Provider (SP) sends an ``AuthnRequest`` to an Identity Provider (IdP)
and later receives and validates a ``Response``. This guide covers both steps.

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

Processing the response
-----------------------

When the IdP posts the ``Response`` back to your ACS:

.. code-block:: python

   from pygamlastan import xml, crypto, security, profiles

   # 1. Cryptographically verify the signature with the trusted IdP certificate.
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
