Worked example: a Service Provider login profile
=================================================

:doc:`writing_profiles` lays out the tiers and primitives. This chapter is the
companion *tutorial*: it builds one complete, real profile - the Service
Provider side of Web Browser SSO - end to end, in pure Python (tier 1-2),
explaining each decision. It is the distilled core of the runnable
``examples/django-sp`` project; pair it with :doc:`sp_integration` for the API
reference of each call.

The profile we are building does four things:

#. resolve the chosen Identity Provider's metadata,
#. build and send an ``AuthnRequest``,
#. receive the ``Response`` at the Assertion Consumer Service (ACS), verify it,
   and validate it,
#. hand the application a clean identity (NameID + attributes).


A reusable profile object
-------------------------

A profile is just a small object that holds configuration and owns the
primitives. Everything below is framework-agnostic; the only inputs are the SP's
own identity (entityID, ACS URL, key/cert) and a way to resolve IdP metadata.

.. code-block:: python

   from pygamlastan import bindings, core, crypto, profiles, security

   class SpLoginProfile:
       def __init__(self, *, entity_id, acs_url, idp_metadata):
           self.entity_id = entity_id
           self.acs_url = acs_url
           self.idp = idp_metadata          # a pygamlastan.metadata.EntityDescriptor
           # State the profile must keep across the two legs of the flow. In a web
           # app these live in the user's session, not on the instance.
           self.replay_cache = security.InMemoryReplayCache()
           self.id_store = InMemoryPersistentIdStore()   # defined below


Step 1 - resolve the IdP
------------------------

The profile needs the IdP's SSO endpoint (where to send the request) and its
signing certificate (to verify the response). Both come from the IdP's metadata,
resolved however your federation works - a trusted local file, or an MDQ lookup
that you signature-verify (see :doc:`sp_integration` for both). Here we just read
what we need from an already-resolved ``EntityDescriptor``:

.. code-block:: python

   def sso_endpoint(self) -> str:
       for ep in self.idp.single_sign_on_services():
           if ep.binding == core.BINDING_HTTP_REDIRECT:
               return ep.location
       raise LookupError("IdP advertises no HTTP-Redirect SSO endpoint")

   def idp_signing_cert(self) -> bytes:
       certs = self.idp.signing_certificates(role="idp")
       if not certs:
           raise LookupError("IdP metadata has no signing certificate")
       return certs[0]


Step 2 - build and send the AuthnRequest
-----------------------------------------

Shape the request with :class:`~pygamlastan.profiles.AuthnRequestOptions`, ask
the IdP to reply over HTTP-POST, and encode the request for the HTTP-Redirect
binding. Keep the returned ``request.id`` - it binds the response to *this*
request in step 3.

.. code-block:: python

   def begin_login(self) -> tuple[str, str]:
       options = profiles.AuthnRequestOptions(
           sp_entity_id=self.entity_id,
           acs_url=self.acs_url,
           destination=self.sso_endpoint(),
           protocol_binding=core.BINDING_HTTP_POST,
           name_id_format=core.NAMEID_PERSISTENT,
       )
       request = profiles.create_authn_request(options)
       redirect_url = bindings.redirect_encode(
           request.to_xml().encode(), is_request=True,
           destination=self.sso_endpoint(),
       )
       return redirect_url, request.id        # redirect the browser; stash request.id

To *sign* the redirect (some IdPs set ``WantAuthnRequestsSigned``), pass a
:class:`~pygamlastan.crypto.SamlSigner` and ``sig_alg`` to ``redirect_encode``.


Step 3 - receive, verify, and validate the Response
----------------------------------------------------

This is where the security lives. The IdP POSTs the ``Response`` to the ACS.
Decode it from the raw form pairs, then hand it to
:func:`~pygamlastan.profiles.process_response_verified`, which verifies the
XML-DSig over the exact bytes with the IdP's signing cert and validates the
result in one call.

.. code-block:: python

   def complete_login(self, form_pairs, expected_request_id):
       decoded = bindings.post_decode(form_pairs)   # list[(name, value)]
       verifier = crypto.SamlVerifier.from_cert(self.idp_signing_cert())
       result = profiles.process_response_verified(
           decoded.saml_text,
           verifier,
           security.SecurityConfig(),               # production-safe defaults
           sp_entity_id=self.entity_id,
           acs_url=self.acs_url,
           expected_idp_entity_id=self.idp.entity_id,
           expected_request_id=expected_request_id,
           replay_cache=self.replay_cache,
           persistent_id_store=self.id_store,
       )
       return result                                 # a profiles.AuthnResult

Three deliberate choices, each a profile rule:

* **Pass the raw form pairs**, not a collapsed ``dict``. ``post_decode`` rejects
  a plain mapping by default because a collapsed map can hide a second smuggled
  ``SAMLResponse``. From Django that is
  ``[(k, v) for k, vs in request.POST.lists() for v in vs]``.
* **Use** :func:`~pygamlastan.profiles.process_response_verified`, not
  ``process_response`` with a hand-passed ``verified_signed_ids`` - the former
  cannot be tricked into "trusting" an unverified response.
* **Supply a** ``persistent_id_store``. Because the request asked for a
  persistent ``NameID``, validation requires a store so a persistent identifier
  cannot be silently re-bound to a different principal.

The persistent-ID store is the one piece of state you must implement. Any backend
works; it fails closed, so a raised exception is treated as a conflict:

.. code-block:: python

   class InMemoryPersistentIdStore:
       def __init__(self):
           self._seen = {}                  # (name_id, sp) -> principal

       def check_and_record(self, name_id, sp_entity_id, principal) -> bool:
           key = (name_id, sp_entity_id)
           existing = self._seen.get(key)
           if existing is None:
               self._seen[key] = principal
               return True
           return existing == principal     # False => reassignment, rejected

In production back this with a database row carrying a unique constraint (see
:doc:`writing_profiles` for the SQL version), so the binding survives restarts
and multiple workers.


Step 4 - use the identity
-------------------------

:class:`~pygamlastan.profiles.AuthnResult` is the clean output - no XML, no
borrowing from the parsed document:

.. code-block:: python

   result = profile.complete_login(form_pairs, expected_request_id)
   user_key = result.name_id                       # stable per-SP identifier
   issuer = result.idp_entity_id
   attrs = result.attributes_dict()                # {name: [values]}
   # e.g. attrs["urn:oid:0.9.2342.19200300.100.1.3"] -> ["alice@example.org"]

Map the wire attribute names to friendly local names with
:doc:`../api/attribute_map` if you prefer ``mail`` over the OID.


Adding a profile rule
----------------------

The 32-check suite ran inside ``process_response_verified``. To enforce a *33rd*
rule specific to your profile, inspect the typed ``AuthnResult`` you already
hold - no need to re-parse. For example, require a step-up authentication
context:

.. code-block:: python

   REQUIRED = core.AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
   if result.authn_context_class_ref != REQUIRED:
       raise PermissionError("insufficient authentication context")

For policy that the validator already understands (tighter windows, encrypted
assertions, signed responses), set the matching
:class:`~pygamlastan.security.SecurityConfig` field instead of writing a check -
see :doc:`writing_profiles` (tier 2) and :doc:`validation`.


Where to go from here
----------------------

* The full, runnable version of this profile - with IdP discovery, MDQ
  resolution, and a Django ACS view - is ``examples/django-sp``.
* The IdP side of the same flow is in :doc:`idp_integration` and
  ``examples/django-idp``.
* For profiles that need messages this binding cannot yet build (Single Logout
  initiation, ECP, artifact resolution), see tier 3 of :doc:`writing_profiles`.
