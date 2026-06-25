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

   class RedisReplayCache:
       def __init__(self, client):
           self.client = client

       def check_and_insert(self, id: str, expiry) -> bool:
           # Atomically set the key only if absent; return True when newly set.
           ttl = max(1, int((expiry - now()).total_seconds()))
           return bool(self.client.set(f"saml:{id}", "1", nx=True, ex=ttl))

       def cleanup(self) -> None:
           pass   # Redis expiry handles eviction

   result = profiles.process_response(..., replay_cache=RedisReplayCache(redis_client))

The object needs two methods: ``check_and_insert(id, expiry) -> bool`` (return
``True`` when the id is new, ``False`` on a replay) and ``cleanup()``. The
adapter fails closed: if your method raises, the id is treated as a replay.
