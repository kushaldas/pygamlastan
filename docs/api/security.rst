pygamlastan.security
====================

.. py:module:: pygamlastan.security

The Web Browser SSO validation suite, its configuration, the structured result,
and the replay cache. See the :doc:`../guides/validation` guide.

.. py:class:: SecurityConfig()

   Controls which checks run and their tolerances. The default constructor uses
   production-safe defaults. Attributes are read/write properties.

   .. py:staticmethod:: permissive() -> SecurityConfig

      Relaxed config for tests only. **Never use in production.**

   .. py:staticmethod:: strict() -> SecurityConfig

      All checks enabled, including the optional ones.

   .. py:attribute:: clock_skew_seconds
      :type: int
   .. py:attribute:: require_signed_assertions
      :type: bool
   .. py:attribute:: require_signed_responses
      :type: bool
   .. py:attribute:: max_assertion_age_seconds
      :type: int
   .. py:attribute:: verify_destination
      :type: bool
   .. py:attribute:: verify_recipient
      :type: bool
   .. py:attribute:: enforce_persistent_id_uniqueness
      :type: bool

.. py:function:: validate_response(response, config, received_url, expected_idp_entity_id, sp_entity_id, acs_url, expected_request_id=None, client_address=None, relay_state=None, response_signature_verified=None, verified_signed_ids=None, current_proxy_depth=0, now=None, replay_cache=None, persistent_id_store=None, unsafe_no_replay_cache=False, unsafe_no_persistent_id_store=False) -> ValidationResult

   Run the full validation suite over a parsed
   :class:`pygamlastan.core.Response` and return a structured
   :class:`ValidationResult` (does not raise on a validation failure).
   ``replay_cache`` is required by default and may be an
   :class:`InMemoryReplayCache` or any object implementing the replay-cache
   protocol. If persistent NameID uniqueness is enabled and the response carries
   a persistent NameID, ``persistent_id_store`` is also required unless
   ``unsafe_no_persistent_id_store=True`` is explicit.

.. py:class:: ValidationResult

   .. py:method:: is_valid() -> bool
   .. py:method:: total_checks() -> int
   .. py:attribute:: checks
      :type: list[ValidationCheck]
   .. py:method:: failures() -> list[ValidationCheck]

.. py:class:: ValidationCheck

   One numbered check from the suite.

   .. py:attribute:: check_number
      :type: int
   .. py:attribute:: check_name
      :type: str
   .. py:attribute:: passed
      :type: bool
   .. py:attribute:: detail
      :type: str | None

Replay cache
------------

.. py:class:: InMemoryReplayCache()

   A single-process replay cache.

   .. py:method:: check_and_insert(id: str, expiry: datetime.datetime) -> bool

      Return ``True`` if ``id`` is new (now recorded), ``False`` if it was
      already seen before ``expiry`` (a replay).

   .. py:method:: cleanup() -> None

.. note::

   For multi-worker deployments, pass any object implementing
   ``check_and_insert(id, expiry) -> bool`` and ``cleanup()`` (for example a
   Redis-backed cache) wherever a ``replay_cache`` is accepted. gamlastan calls
   into it and fails closed if a call raises. See
   :doc:`../guides/validation`.
