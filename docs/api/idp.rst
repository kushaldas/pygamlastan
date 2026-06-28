pygamlastan.idp
===============

.. py:module:: pygamlastan.idp

IdP-side infrastructure: eduPersonTargetedID generation, the authentication
broker, NameID storage coding, and an issued-assertion store.

eduPersonTargetedID
-------------------

.. py:class:: Eptid(secret: str)

   Derives stable, per-SP opaque identifiers from a server-side ``secret``. The
   same user gets a consistent id at one SP but an unlinkable id at another.

   .. py:method:: get(idp_entity_id: str, sp_entity_id: str, user_id: str) -> str
   .. py:method:: name_id(idp_entity_id: str, sp_entity_id: str, user_id: str) -> pygamlastan.core.NameId
   .. py:method:: attribute(idp_entity_id: str, sp_entity_id: str, user_id: str) -> pygamlastan.core.Attribute

Authentication broker
---------------------

.. py:class:: AuthnBroker()

   Registers authentication methods and selects them by authentication context.

   .. py:method:: add(class_ref: str, method: str, level: int, authn_authority: str | None = None) -> str

      Register a method; returns its reference id.

   .. py:method:: get_by_class_ref(class_ref: str) -> AuthnMethod | None
   .. py:method:: pick(requested: pygamlastan.core.RequestedAuthnContext | None = None) -> list[AuthnMethod]

      Methods matching a requested context (best first); with ``None``, performs
      the unspecified-context lookup.

.. py:class:: AuthnMethod

   ``class_ref``, ``method``, ``level`` (int), ``authn_authority`` (str | None),
   ``reference``.

Assertion store
---------------

.. py:class:: InMemoryAssertionStore()

   Retains issued assertions to answer later queries.

   .. py:method:: store_assertion(assertion: pygamlastan.core.Assertion) -> None
   .. py:method:: get_assertion(assertion_id: str) -> pygamlastan.core.Assertion | None
   .. py:method:: assertions_for_subject(name_id_value: str) -> list[pygamlastan.core.Assertion]
   .. py:method:: remove_assertion(assertion_id: str) -> None

Identity database
-----------------

.. py:class:: IdentDb(idp_entity_id: str, store: IdentityStore | None = None, domain: str | None = None)

   The IdP identity database (pysaml2 ``IdentDB``): the bidirectional mapping
   between local user ids and the NameIDs issued to relying parties, NameID
   generation honoring an incoming ``NameIDPolicy``, and the server side of the
   ManageNameID / NameIDMapping profiles.

   ``idp_entity_id`` is the default NameQualifier. With ``store=None`` the
   database is in-memory; pass an object implementing ``get(key)`` /
   ``set(key, value)`` / ``remove(key)`` (the ``IdentityStore`` protocol) to back
   it with Redis/SQL/Mongo. ``domain`` is appended to email-format NameIDs.

   .. py:method:: store(user_id: str, name_id: pygamlastan.core.NameId) -> None

      Associate a NameID with a local user (maintains both directions).

   .. py:method:: find_local_id(name_id: pygamlastan.core.NameId) -> str | None

      The local user a NameID was issued to, if known.

   .. py:method:: name_ids_for(user_id: str) -> list[pygamlastan.core.NameId]
   .. py:method:: match_local_id(user_id: str, sp_name_qualifier: str | None = None, name_qualifier: str | None = None) -> pygamlastan.core.NameId | None

      An existing non-transient NameID matching (user, SP, NameQualifier).

   .. py:method:: transient_nameid(user_id: str, sp_name_qualifier: str | None = None) -> pygamlastan.core.NameId

      A fresh, unique transient NameID.

   .. py:method:: persistent_nameid(user_id: str, sp_name_qualifier: str | None = None) -> pygamlastan.core.NameId

      A stable persistent NameID for (user, SP) - reused across calls.

   .. py:method:: construct_nameid(user_id: str, sp_entity_id: str, name_id_policy: pygamlastan.core.NameIdPolicy | None = None, default_format: str | None = None) -> pygamlastan.core.NameId

      Construct a NameID honoring the request ``NameIDPolicy`` (format,
      SPNameQualifier, AllowCreate), falling back to ``default_format``. Raises
      :class:`pygamlastan.SamlIdentError` if no format is determined or
      AllowCreate forbids minting a persistent id.

   .. py:method:: manage_name_id_new_id(name_id: pygamlastan.core.NameId, new_id: str) -> pygamlastan.core.NameId

      Apply a ManageNameID ``NewID`` (record the SP-provided identifier).

   .. py:method:: manage_name_id_terminate(name_id: pygamlastan.core.NameId) -> pygamlastan.core.NameId

      Apply a ManageNameID ``Terminate`` (drop the association).

   .. py:method:: handle_name_id_mapping_request(name_id: pygamlastan.core.NameId, name_id_policy: pygamlastan.core.NameIdPolicy) -> pygamlastan.core.NameId

      Resolve a NameIDMappingRequest: an existing matching NameID, or a new one
      when AllowCreate permits. Raises :class:`pygamlastan.SamlIdentError`.

   .. py:method:: remove_remote(name_id: pygamlastan.core.NameId) -> None
   .. py:method:: remove_local(user_id: str) -> None

   The ManageNameID ``NewID``/``Terminate`` operations are exposed as the two
   ``manage_name_id_*`` methods rather than a Python ``NewIdOrTerminate`` union;
   ``NewEncryptedID`` (which requires decryption first) is not supported.

.. py:class:: IdentityStore

   Protocol for a pluggable :class:`IdentDb` backend.

   .. py:method:: get(key: str) -> str | None
   .. py:method:: set(key: str, value: str) -> None
   .. py:method:: remove(key: str) -> None

Attribute-release policy
------------------------

The release policy (pysaml2 ``Policy``) decides which attributes - and which
values - the IdP releases to each SP. Per-knob resolution is: the SP-specific
entry, then the SP's registration-authority entry (when recorded), then the
``"default"`` entry, then a built-in default.

.. py:class:: ReleasePolicy(default: PolicyEntry | None = None)

   .. py:method:: insert(sp_entity_id: str, entry: PolicyEntry) -> None

      Add or replace the entry for an SP entity id (or ``"default"``).

   .. py:method:: set_registration_authority(sp_entity_id: str, registration_authority: str) -> None

      Map an SP to a registration authority so resolution can fall back to a
      per-authority entry when the SP has no entry of its own.

   .. py:method:: register_sp_metadata(entity: pygamlastan.metadata.EntityDescriptor) -> None

      Read ``mdrpi:RegistrationInfo/@registrationAuthority`` from parsed SP
      metadata and record it. No-op when the metadata declares none.

   .. py:method:: nameid_format(sp_entity_id: str) -> str
   .. py:method:: name_form(sp_entity_id: str) -> str
   .. py:method:: lifetime_seconds(sp_entity_id: str) -> int
   .. py:method:: not_on_or_after(sp_entity_id: str, now: datetime.datetime) -> datetime.datetime
   .. py:method:: sign(sp_entity_id: str) -> SignTargets
   .. py:method:: fail_on_missing_requested(sp_entity_id: str) -> bool

   .. py:method:: filter(attributes: list[pygamlastan.core.Attribute], sp_entity_id: str, sp_entity_categories: list[str] | None = None, required: list[pygamlastan.core.Attribute] | None = None, optional: list[pygamlastan.core.Attribute] | None = None, subject_id_req: str = "none") -> list[pygamlastan.core.Attribute]

      Filter ``attributes`` for release to the SP. ``required`` / ``optional``
      are the SP's requested attributes (a value list on a requested attribute
      narrows the released values). ``sp_entity_categories`` are the SP's
      published category URIs (read from its metadata ``EntityAttributes`` under
      :data:`ENTITY_CATEGORY_ATTR`); entity-category release takes precedence
      over requested/optional matching when the entry configures it.
      ``subject_id_req`` is one of ``"none"``, ``"subject-id"``,
      ``"pairwise-id"``, ``"any"`` (with ``"any"`` and both ids present,
      ``subject-id`` is dropped in favour of ``pairwise-id``). Raises
      :class:`pygamlastan.SamlPolicyError` if a required attribute/value is
      missing and ``fail_on_missing_requested`` is set.

.. py:class:: PolicyEntry(nameid_format: str | None = None, name_form: str | None = None, lifetime_seconds: int | None = None, sign: SignTargets | None = None, fail_on_missing_requested: bool | None = None, entity_categories: list[str] | None = None, owned_entity_categories: list[EntityCategoryPolicy] | None = None, attribute_restrictions: list[tuple[str, list[str] | None]] | None = None)

   One policy entry. ``entity_categories`` names shipped policies (e.g.
   ``["swamid"]``); ``owned_entity_categories`` supplies developer-built ones;
   the two are merged. ``attribute_restrictions`` maps a local attribute name to
   a list of value patterns (anchored, ``re.match`` semantics) or ``None`` for
   all values; attributes not named are not released. Raises
   :class:`pygamlastan.SamlPolicyError` if a pattern fails to compile.

.. py:class:: SignTargets(response: bool = False, assertion: bool = False, on_demand: bool = False)

   Which messages the IdP signs for an SP. ``on_demand`` signs the assertion
   when the SP's metadata sets ``WantAssertionsSigned``.

   .. py:method:: resolve(sp_wants_assertions_signed: bool) -> ResolvedSignTargets

.. py:class:: ResolvedSignTargets

   The concrete decision: ``sign_response`` / ``sign_assertion``.

Entity categories
-----------------

.. py:class:: EntityCategoryRule(categories: list[str], attributes: list[str], conflicts: list[str] | None = None, only_required: bool = False)

   A release rule: releases ``attributes`` (local names) when *all* of
   ``categories`` are present on the SP and *none* of ``conflicts`` is. With
   ``only_required`` only the subset the SP also marks required is released
   (CoCo semantics). Properties mirror the constructor.

.. py:class:: EntityCategoryPolicy(name: str, rules: list[EntityCategoryRule] | None = None, extend: str | None = None)

   A named set of rules. ``extend`` seeds it from a shipped policy (by name)
   before appending ``rules``.

   .. py:staticmethod:: shipped(name: str) -> EntityCategoryPolicy

      A shipped policy as an owned, extensible value. Known names: ``edugain``,
      ``refeds``, ``incommon``, ``swamid``, ``refeds-access``, ``at_egov_pvp2``.

.. py:function:: releasable_attributes(policies: list[EntityCategoryPolicy], sp_entity_categories: list[str], required_local_names: list[str] | None = None) -> list[str]

   The releasable local (lowercased) attribute names for the given policies and
   the SP's published categories - the entity-category engine on its own.

.. py:function:: subject_id_req_from_metadata(values: list[str]) -> str

   Parse the SP's ``subject-id:req`` metadata values into ``"none"`` /
   ``"subject-id"`` / ``"pairwise-id"`` / ``"any"``.

Module constants: the entity-category URIs (``COCO_V1``, ``COCO_V2``,
``REFEDS_RESEARCH_AND_SCHOLARSHIP``, ``INCOMMON_RESEARCH_AND_SCHOLARSHIP``,
``MYACADEMICID_ESI``, ``REFEDS_PERSONALIZED``, ``REFEDS_PSEUDONYMOUS``,
``REFEDS_ANONYMOUS``, ``AT_EGOV_PVP2``, ``AT_EGOV_PVP2_CHARGE``), the
``ENTITY_CATEGORY_ATTR`` metadata attribute name SPs publish categories under,
and the subject-id profile attribute names (``SUBJECT_ID_ATTR``,
``PAIRWISE_ID_ATTR``, ``SUBJECT_ID_REQ_ATTR``).

NameID storage coding
---------------------

.. py:function:: code_name_id(name_id: pygamlastan.core.NameId) -> str

   Serialize a NameID to an opaque storage string.

.. py:function:: decode_name_id(coded: str) -> pygamlastan.core.NameId

   Parse a NameID from its storage string.
