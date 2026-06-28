Quickstart
==========

This page walks through a complete Web Browser SSO exchange using the in-process
helpers, so you can run it end to end without a network or a real IdP/SP.

Service Provider: process a response
------------------------------------

Given the XML of a SAML ``Response`` received at your Assertion Consumer Service
(ACS) endpoint, the safe entry point is
:func:`~pygamlastan.profiles.process_response_verified`. It performs the
XML-DSig verification **internally over the exact bytes it validates**, so the
"verified" signatures cannot drift from the assertion you trust:

.. code-block:: python

   from pygamlastan import crypto, security, profiles

   verifier = crypto.SamlVerifier.from_cert(idp_certificate_pem)   # trusted IdP cert

   result = profiles.process_response_verified(
       response_xml,                                # raw bytes as received
       verifier,
       security.SecurityConfig(),                   # production defaults
       sp_entity_id="https://sp.example.org/sp",
       acs_url="https://sp.example.org/acs",
       expected_idp_entity_id="https://idp.example.org",
       expected_request_id="_the_request_id",       # None for unsolicited
       replay_cache=security.InMemoryReplayCache(),
   )

   print(result.name_id)
   print(result.attributes_dict())   # {"mail": ["alice@example.org"], ...}

.. important::

   Prefer ``process_response_verified``. The lower-level
   :func:`~pygamlastan.profiles.process_response` trusts a caller-supplied
   ``verified_signed_ids`` and does **not** verify signatures itself — passing
   that without a real verification is an authentication bypass. See the
   :doc:`security guide <guides/security>`.

Identity Provider: build a response
-----------------------------------

On the IdP side, turn an authenticated principal into a SAML ``Response``:

.. code-block:: python

   from pygamlastan import core, profiles

   options = profiles.ResponseOptions(
       idp_entity_id="https://idp.example.org",
       sp_entity_id="https://sp.example.org/sp",
       acs_url="https://sp.example.org/acs",
       in_response_to="_the_request_id",
       authn_context_class_ref=core.AUTHN_CONTEXT_PASSWORD,
       attributes=[
           core.Attribute("mail", values=["alice@example.org"]),
           core.Attribute("displayName", values=["Alice"]),
       ],
   )
   name_id = core.NameId("alice@example.org", format=core.NAMEID_TRANSIENT)
   response = profiles.create_response(options, name_id)

   unsigned_xml = response.to_xml()   # next: sign it (see the signing guide)

A full round trip
------------------

Putting both sides together, with ``permissive`` validation so the example does
not require real signatures:

.. code-block:: python

   from datetime import datetime, timezone
   from pygamlastan import core, xml, profiles, security

   now = datetime(2026, 6, 25, 10, 0, 0, tzinfo=timezone.utc)
   IDP, SP, ACS = "https://idp.example.org", "https://sp.example.org/sp", "https://sp.example.org/acs"

   # IdP issues a response for request "_req1".
   options = profiles.ResponseOptions(
       IDP, SP, ACS, in_response_to="_req1",
       authn_context_class_ref=core.AUTHN_CONTEXT_PASSWORD,
       attributes=[core.Attribute("mail", values=["alice@example.org"])],
   )
   response = profiles.create_response(options, core.NameId("alice", format=core.NAMEID_TRANSIENT), now=now)

   # SP consumes it.
   parsed = xml.parse_response(response.to_xml())
   result = profiles.process_response(
       parsed, security.SecurityConfig.permissive(), SP, ACS, IDP,
       expected_request_id="_req1", now=now, replay_cache=security.InMemoryReplayCache(),
   )
   assert result.name_id == "alice"

Where to go next
----------------

* :doc:`guides/security` is the most important next read: the trust-coupling
  model, XXE/DTD input hardening, authentication freshness, and the footguns to
  avoid.
* :doc:`guides/sp_integration` and :doc:`guides/idp_integration` cover each side
  in depth, including the AuthnRequest.
* :doc:`guides/signing` explains file-key and PKCS#11/HSM signing and
  verification.
* :doc:`guides/validation` documents the security configuration, the structured
  validation result, and replay protection.
