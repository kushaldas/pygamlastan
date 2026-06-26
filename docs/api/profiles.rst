pygamlastan.profiles
====================

.. py:module:: pygamlastan.profiles

Web Browser SSO for both the SP and IdP sides. See the
:doc:`../guides/sp_integration` and :doc:`../guides/idp_integration` guides.
Errors raise :class:`pygamlastan.SamlProfileError`.

Service Provider
----------------

.. py:class:: AuthnRequestOptions(sp_entity_id, acs_url=None, acs_index=None, protocol_binding=None, force_authn=None, is_passive=None, name_id_format=None, allow_create=True, sp_name_qualifier=None, authn_context_class_refs=None, authn_context_comparison=None, provider_name=None, destination=None, proxy_count=None, requester_ids=None, attribute_consuming_service_index=None, extensions=None)

   Inputs to :func:`create_authn_request`. ``authn_context_comparison`` is one of
   ``"exact"``, ``"minimum"``, ``"maximum"``, ``"better"``.

.. py:function:: create_authn_request(options: AuthnRequestOptions) -> pygamlastan.core.AuthnRequest

   Build an (unsigned) ``AuthnRequest`` from ``options``.

.. py:function:: process_response(response, config, sp_entity_id, acs_url, expected_idp_entity_id, expected_request_id=None, verified_signed_ids=None, now=None, replay_cache=None, persistent_id_store=None, unsafe_no_replay_cache=False, unsafe_no_persistent_id_store=False) -> AuthnResult

   Validate a :class:`pygamlastan.core.Response` and extract the identity. Pass
   ``verified_signed_ids`` from a trusted
   :class:`pygamlastan.crypto.SamlVerifier` to enforce signed assertions, and a
   ``replay_cache`` to detect assertion replay. ``replay_cache`` is required by
   default; pass ``unsafe_no_replay_cache=True`` only for legacy unsafe
   processing. If persistent NameID uniqueness is enabled, persistent NameID
   responses also require ``persistent_id_store`` unless explicitly waived.
   Raises
   :class:`pygamlastan.SamlProfileError` on any validation failure.

.. py:function:: process_response_verified(response_xml, verifier, config, sp_entity_id, acs_url, expected_idp_entity_id, expected_request_id=None, now=None, replay_cache=None, persistent_id_store=None, unsafe_no_replay_cache=False, unsafe_no_persistent_id_store=False) -> AuthnResult

   The **safe, preferred SP entry point**. It performs XML-DSig verification with
   ``verifier`` over the *exact* ``response_xml`` bytes and feeds only the
   cryptographically verified reference IDs into validation - so the caller
   cannot assert "this was signed" without real crypto, closing the
   auth-bypass-by-mis-integration gap that hand-passing ``verified_signed_ids``
   to :func:`process_response` leaves open. Raises
   :class:`pygamlastan.SamlCryptoError` if the signature is missing or invalid,
   and :class:`pygamlastan.SamlProfileError` on any validation failure.
   ``replay_cache`` is required by default (see :func:`process_response` for the
   ``unsafe_*`` waivers and the ``persistent_id_store`` requirement).

.. py:class:: AuthnResult

   The authenticated identity extracted from a response.

   .. py:attribute:: name_id
      :type: str
   .. py:attribute:: name_id_format
      :type: str | None
   .. py:attribute:: name_qualifier
      :type: str | None
   .. py:attribute:: sp_name_qualifier
      :type: str | None
   .. py:attribute:: session_index
      :type: str | None
   .. py:attribute:: session_not_on_or_after
   .. py:attribute:: authn_instant
   .. py:attribute:: authn_context_class_ref
      :type: str | None
   .. py:attribute:: authenticating_authorities
      :type: list[str]
   .. py:attribute:: attributes
      :type: list[pygamlastan.core.Attribute]
   .. py:method:: attributes_dict() -> dict[str, list[str]]

      Attributes as ``{name: [values]}`` (string values only).

   .. py:attribute:: idp_entity_id
      :type: str
   .. py:attribute:: assertion_id
      :type: str
   .. py:attribute:: response_id
      :type: str

Identity Provider
-----------------

.. py:function:: process_authn_request(request, sp_metadata=None, unsafe_allow_missing_metadata=False) -> ProcessedAuthnRequest

   Distil an incoming ``AuthnRequest`` into the fields needed to build a
   response. ``sp_metadata`` (a :class:`pygamlastan.metadata.EntityDescriptor`)
   is required by default so the ACS endpoint is resolved against trusted
   metadata. Pass ``unsafe_allow_missing_metadata=True`` only for legacy unsafe
   processing.

.. py:class:: ProcessedAuthnRequest

   ``request_id``, ``sp_entity_id``, ``acs_url``, ``acs_binding``,
   ``force_authn``, ``is_passive``, ``requested_name_id_format``,
   ``allow_create``, ``requested_authn_context_class_refs``,
   ``attribute_consuming_service_index``.

.. py:class:: ResponseOptions(idp_entity_id, sp_entity_id, acs_url, assertion_lifetime_seconds=300, in_response_to=None, session_index=None, session_not_on_or_after=None, authn_context_class_ref=None, client_address=None, attributes=None)

   Inputs to :func:`create_response`. ``attributes`` is a list of
   :class:`pygamlastan.core.Attribute`.

.. py:function:: create_response(options: ResponseOptions, principal_name_id, now=None) -> pygamlastan.core.Response

   Build a ``Response`` carrying an assertion for ``principal_name_id`` (a
   :class:`pygamlastan.core.NameId`).

.. py:function:: create_unsolicited_response(idp_entity_id, sp_entity_id, acs_url, principal_name_id, attributes=None, authn_context_class_ref=None, assertion_lifetime_seconds=300, session_index=None, session_not_on_or_after=None, client_address=None, now=None) -> pygamlastan.core.Response

   Build an IdP-initiated (unsolicited) ``Response`` with no ``InResponseTo``.

Sessions
--------

.. py:class:: InMemorySessionStore()

   A single-process store of SSO sessions for Single Logout.

   .. py:method:: destroy_session(session_index: str) -> bool
   .. py:method:: cleanup_expired() -> None
