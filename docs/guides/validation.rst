Validation and replay protection
================================

When you call :func:`pygamlastan.profiles.process_response`, gamlastan runs a
full Web Browser SSO validation suite (destination, audience, conditions,
subject confirmation, signatures, replay, and more). The :doc:`../api/security`
module exposes the configuration, a structured result, and the replay cache.

Configuration
-------------

:class:`pygamlastan.security.SecurityConfig` controls the checks. Use the
production defaults, or a preset:

.. code-block:: python

   from pygamlastan import security

   cfg = security.SecurityConfig()              # production-safe defaults
   cfg.clock_skew_seconds = 120                 # tunable properties
   cfg.require_signed_assertions = True

   strict = security.SecurityConfig.strict()    # all checks, incl. optional ones
   loose = security.SecurityConfig.permissive() # TESTS ONLY, not for production

All validation knobs are regular properties:

.. code-block:: python

   cfg = security.SecurityConfig()

   # Signature policy.
   cfg.require_signed_assertions = True          # each Assertion has its own signature
   cfg.require_signed_responses = False          # require Response envelope signature

   # Time and endpoint policy.
   cfg.clock_skew_seconds = 180
   cfg.max_assertion_age_seconds = 300
   cfg.verify_destination = True
   cfg.verify_recipient = True
   cfg.check_client_address = False              # enable only when Address is meaningful

   # Optional high-security/profile policy.
   cfg.require_encrypted_assertions = False

   # SAML errata hardening, all enabled by default.
   cfg.reject_signatures_with_ds_object = True    # E91 / XSW hardening
   cfg.enforce_persistent_id_uniqueness = True    # E78
   cfg.sanitize_relay_state = True                # E90
   cfg.require_integrity_with_cbc = True          # E93

.. warning::

   ``permissive()`` relaxes signature and other requirements and must never be
   used in production. It exists so examples and tests can run without real
   signatures.

Inspecting the result
---------------------

:func:`pygamlastan.security.validate_response` returns a structured
:class:`~pygamlastan.security.ValidationResult` instead of raising, so you can
inspect every check. (``process_response`` raises
:class:`~pygamlastan.SamlProfileError` on the first failure; use
``validate_response`` when you want the detail.)

.. code-block:: python

   result = security.validate_response(
       response, cfg,
       received_url="https://sp.example.org/acs",
       expected_idp_entity_id="https://idp.example.org",
       sp_entity_id="https://sp.example.org/sp",
       acs_url="https://sp.example.org/acs",
       expected_request_id="_req1",
       replay_cache=security.InMemoryReplayCache(),
   )

   if not result.is_valid():
       for check in result.failures():
           print(check.check_number, check.check_name, check.detail)

   # Individual outcomes are addressable for profile-specific logic.
   age = result.get(0)
   audience = result.by_name("Audience restriction")
   passed = result.passed_checks()

Lower-level validation with your own signature verifier
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For normal SP login handling, prefer
:func:`pygamlastan.profiles.process_response_verified`. If you deliberately use
``validate_response`` directly, verify the exact bytes first and pass only IDs
reported by the verifier:

.. code-block:: python

   from pygamlastan import crypto, security, xml

   verifier = crypto.SamlVerifier.from_cert(idp_certificate_pem)
   verifier.set_skip_time_checks(False)
   verifier.set_trusted_keys_only(True)
   verifier.set_strict_verification(True)
   verifier.set_hmac_min_out_len(160)
   verifier.set_require_reference_digests(True)
   verifier.set_allow_raw_inline_keyinfo_with_trust_anchors(False)
   verify_results = verifier.verify_all_enveloped(response_xml)
   if not verify_results or any(not result.is_valid() for result in verify_results):
       raise ValueError("SAML response signature verification failed")
   signed_ids = [
       signed_id
       for verify_result in verify_results
       for signed_id in verify_result.signed_reference_ids()
   ]

   response = xml.parse_response(response_xml)
   validation = security.validate_response(
       response,
       security.SecurityConfig(),
       received_url="https://sp.example.org/acs",
       expected_idp_entity_id="https://idp.example.org",
       sp_entity_id="https://sp.example.org/sp",
       acs_url="https://sp.example.org/acs",
       expected_request_id="_req1",
       verified_signed_ids=signed_ids,
       replay_cache=security.InMemoryReplayCache(),
   )

Replay protection
-----------------

A replay cache rejects an assertion id that has already been seen. Use the
built-in in-memory cache for a single process:

.. code-block:: python

   cache = security.InMemoryReplayCache()
   cache.check_and_insert("id-1", expiry)   # True the first time, False on replay

Custom backends (Redis, a database, ...)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A single-process in-memory cache is not enough for a multi-worker deployment
(each worker would have its own state). Pass any object implementing the replay
cache protocol and gamlastan calls into it:

.. code-block:: python

   from datetime import datetime, timezone

   class RedisReplayCache:
       def __init__(self, client):
           self.client = client

       def check_and_insert(self, id: str, expiry) -> bool:
           # Atomically set the key only if absent; return True when newly set.
           ttl = max(1, int((expiry - datetime.now(timezone.utc)).total_seconds()))
           return bool(self.client.set(f"saml:{id}", "1", nx=True, ex=ttl))

       def cleanup(self) -> None:
           pass   # Redis expiry handles eviction

   result = profiles.process_response(..., replay_cache=RedisReplayCache(redis_client))

The object needs two methods: ``check_and_insert(id, expiry) -> bool`` (return
``True`` when the id is new, ``False`` on a replay) and ``cleanup()``. The
adapter fails closed: if your method raises, the id is treated as a replay.

Persistent NameID store
-----------------------

``enforce_persistent_id_uniqueness`` is opt-in (it defaults to off); enable it
explicitly when your SP correlates persistent ``NameID`` values with local
accounts. With it enabled, a response that carries a persistent ``NameID`` also
needs a store that prevents the same identifier from being rebound to a
different local principal:

.. code-block:: python

   class PersistentIdStore:
       def __init__(self, db):
           self.db = db

       def check_and_record(self, name_id: str, sp_entity_id: str, principal: str) -> bool:
           existing = self.db.get((name_id, sp_entity_id))
           if existing is None:
               self.db[(name_id, sp_entity_id)] = principal
               return True
           return existing == principal

   result = security.validate_response(
       response, cfg,
       received_url="https://sp.example.org/acs",
       expected_idp_entity_id="https://idp.example.org",
       sp_entity_id="https://sp.example.org/sp",
       acs_url="https://sp.example.org/acs",
       replay_cache=security.InMemoryReplayCache(),
       persistent_id_store=PersistentIdStore({}),
       # The local account id resolved independently of the asserted NameID.
       persistent_id_principal="local-account-42",
   )

The object needs ``check_and_record(name_id, sp_entity_id, principal) -> bool``.
Returning ``False`` or raising fails the validation check closed.
``persistent_id_principal`` is required alongside the store: gamlastan keys the
uniqueness check by this independent local principal, never by the asserted
NameID (which could never detect a reassignment).
