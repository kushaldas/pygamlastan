pygamlastan.logout
==================

.. py:module:: pygamlastan.logout

SAML 2.0 Single Logout (SLO). This module surfaces the SP-initiated logout
surface - the equivalent of pysaml2's ``global_logout`` /
``handle_logout_response`` loop - plus the ``LogoutResponse`` builders both
roles need and an incoming-request validator.

The :class:`SpLogoutOrchestrator` is a transport-agnostic state machine: it
never performs I/O. You register the entities that hold a session for the
principal, then loop "get next request -> deliver over the binding it tells you
-> feed the response back" until it reports completion.

Building requests
-----------------

.. py:class:: SpLogoutRequestOptions(sp_entity_id: str, name_id: pygamlastan.core.NameId, session_indexes: list[str] | None = None, reason: str | None = None, destination: str | None = None, not_on_or_after: datetime.datetime | None = None)

   Inputs for an SP-initiated ``<samlp:LogoutRequest>``. ``not_on_or_after``
   defaults to five minutes from now.

.. py:function:: create_sp_logout_request(options: SpLogoutRequestOptions) -> pygamlastan.core.LogoutRequest

   Build the LogoutRequest. Sign it (``crypto``) before front-channel delivery.
   Raises :class:`pygamlastan.SamlProfileError` if the SP entity id is empty.

Building responses
------------------

.. py:function:: create_logout_response_success(entity_id: str, in_response_to: str, destination: str | None = None) -> pygamlastan.core.LogoutResponse

   A ``Success`` LogoutResponse.

.. py:function:: create_logout_response_partial(entity_id: str, in_response_to: str, destination: str | None = None) -> pygamlastan.core.LogoutResponse

   Top-level ``Success`` with a ``PartialLogout`` sub-status (some session
   participants could not be logged out).

.. py:function:: create_logout_response_error(entity_id: str, in_response_to: str, status_code: str, status_message: str | None = None, destination: str | None = None) -> pygamlastan.core.LogoutResponse

   An error LogoutResponse carrying ``status_code`` (e.g.
   :data:`pygamlastan.core.STATUS_RESPONDER`) and an optional message.

Validating requests
--------------------

.. py:function:: validate_logout_request(request: pygamlastan.core.LogoutRequest, expected_issuer: str, signature_verified: bool, now: datetime.datetime, clock_skew_seconds: int = 180) -> None

   Check that the ``Issuer`` exactly matches ``expected_issuer`` (the trusted
   peer's entity ID), the NameID is present, and (if set) ``NotOnOrAfter`` has
   not expired, allowing ``clock_skew_seconds`` of skew. Raises
   :class:`pygamlastan.SamlProfileError` if invalid.

   ``signature_verified`` must reflect cryptographic verification of *this exact
   message* performed by your transport layer (a Redirect-binding query
   signature and/or an enveloped XML-DSig checked with a real
   :class:`pygamlastan.crypto.SamlVerifier` against the peer's metadata keys).
   SLO destroys the session keyed by the request-supplied NameID, so passing a
   hard-coded ``True`` would let anyone who guesses a NameID force-log a victim
   out; the check fails closed when ``signature_verified`` is ``False``.

SP-side orchestration
---------------------

.. py:class:: SpLogoutOrchestrator(sp_entity_id: str, reason: str | None = None)

   Drives SP-initiated logout across every entity that holds a session for the
   principal. ``reason`` defaults to :data:`REASON_USER`.

   .. py:method:: add_target(target: LogoutTarget) -> None

      Register an entity that must be logged out.

   .. py:method:: next_request() -> PendingLogoutRequest | None

      The next request to deliver (marking that target in-progress), or ``None``
      when no target is pending.

   .. py:method:: handle_response(response: pygamlastan.core.LogoutResponse, signature_verified: bool) -> LogoutResponseOutcome

      Correlate a response with its outstanding request by ``InResponseTo`` and
      record the outcome. ``signature_verified`` must reflect cryptographic
      verification of *this exact response* by your transport layer; correlation
      alone must not authenticate it, or a forged success would mark a
      participant logged out while its session lives. Raises
      :class:`pygamlastan.SamlProfileError` if the response was not verified,
      matches no outstanding request, has no issuer, or its issuer does not match
      the target (anti-spoofing).

   .. py:method:: mark_failed(entity_id: str, failure_reason: str) -> None

      Record a transport-level failure (e.g. the SOAP call failed or a
      front-channel response never arrived).

   .. py:method:: target_state(entity_id: str) -> TargetLogoutState | None
   .. py:method:: is_complete() -> bool

      Whether every target reached a final state (succeeded or failed).

   .. py:method:: progress() -> LogoutPropagationResult

.. py:class:: LogoutTarget(entity_id: str, name_id: pygamlastan.core.NameId, slo_url: str, slo_binding: str, session_indexes: list[str] | None = None)

   A session authority/participant to log out from. Exposes ``entity_id``,
   ``slo_url``, ``slo_binding``, and ``session_indexes`` as read-only
   properties.

.. py:class:: PendingLogoutRequest

   A request ready to deliver. Properties: ``entity_id``, ``request``
   (:class:`pygamlastan.core.LogoutRequest`), ``binding``, ``destination``.

.. py:class:: LogoutResponseOutcome

   Result of correlating one response. Properties: ``entity_id``, ``success``,
   ``partial`` (the entity reported ``PartialLogout``).

.. py:class:: TargetLogoutState

   The state of one target. ``kind`` is one of ``"pending"``,
   ``"in_progress"``, ``"succeeded"``, ``"failed"``. ``request_id`` is set for
   ``in_progress``; ``reason`` is set for ``failed``.

.. py:class:: LogoutPropagationResult

   Aggregate progress. Properties ``total_participants``, ``successful_logouts``,
   ``failed_participants``; methods :py:meth:`is_complete` and
   :py:meth:`is_partial`.

Constants
---------

.. py:data:: REASON_USER

   ``urn:oasis:names:tc:SAML:2.0:logout:user``.

.. py:data:: REASON_ADMIN

   ``urn:oasis:names:tc:SAML:2.0:logout:admin``.
