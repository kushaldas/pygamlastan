pygamlastan.idp
===============

.. py:module:: pygamlastan.idp

IdP-side infrastructure: eduPersonTargetedID generation, the authentication
broker, NameID storage coding, an issued-assertion store, and the
:class:`ResponseEngine` that composes them into the Web Browser SSO response
flow.

eduPersonTargetedID
-------------------

.. py:class:: Eptid(secret: str, digest: str = "sha256", allow_legacy_md5: bool = False, store: KeyValueStore | None = None, verify_store: bool = True)

   Derives stable, per-SP opaque identifiers from a server-side ``secret``. The
   same user gets a consistent id at one SP but an unlinkable id at another.

   ``digest`` is ``"sha256"`` (default) or ``"pysaml2-md5"`` (which emits a
   ``UserWarning``, since MD5 is in use). The latter
   reproduces stock pysaml2's ``idp!sp!md5(user+sp+secret)`` values, so SPs that
   key accounts on the EPTID keep seeing the same value after a migration. It
   is rejected (``SamlIdentError``) unless ``allow_legacy_md5=True``; use it only
   when the old IdP entityID, SP entityID, user identifier and secret are all
   unchanged, and plan its retirement. Methods raise ``SamlStoreError`` on a
   storage failure.

   Issued values are remembered in a cache, so a later change of secret or
   digest cannot change what an SP already knows. By default it is in memory and
   lost on restart; pass ``store`` to persist it.

   .. py:class:: KeyValueStore

      Protocol for the ``store`` argument: ``get(key: str) -> str | None``,
      ``set(key: str, value: str) -> None`` and ``remove(key: str) -> None``.
      Any exception is a backend failure and surfaces as
      :class:`pygamlastan.SamlStoreError`; never return ``None`` for a backend
      that could not answer, because a recompute could issue a different value
      than the one already issued. The store is trusted: what it returns is the
      identifier issued, after one check: it must have the shape
      ``<idp>!<sp>!<opaque>`` with no ``!`` in the opaque part (an entity ID may
      contain one, so ``<idp>!<sp>!x!y`` could be another SP's), otherwise
      :class:`pygamlastan.SamlStoreError`. Pass ``verify_store=False`` for values
      issued under an earlier IdP entity ID, or a cache you fully trust. That
      catches a cache shared with another IdP or tenant, a key written by the
      wrong code, or a restored or flushed cache; it cannot catch a forged value
      of the right shape. The cache must be private to this IdP and this secret,
      and must not evict issued values (no TTL).

      Keys are ``eptid:<idp>__<sp>__<user>`` and values are ``idp!sp!hash``
      strings, the same shape pysaml2 stores. pysaml2 keys its cache
      ``<sp>__<user>`` instead, so an adapter over an existing pysaml2 shelve or
      Mongo ``eptid`` collection must translate the key; entity IDs that contain
      ``__`` make that split ambiguous. This matters only when the old store
      holds values that recomputation would not reproduce (a changed secret,
      hand-edited or imported entries). With ``digest="pysaml2-md5"`` and an
      unchanged secret, the values are reproduced without it.

   .. py:method:: get(idp_entity_id: str, sp_entity_id: str, user_id: str) -> str
   .. py:method:: name_id(idp_entity_id: str, sp_entity_id: str, user_id: str) -> pygamlastan.core.NameId
   .. py:method:: attribute(idp_entity_id: str, sp_entity_id: str, user_id: str) -> pygamlastan.core.Attribute

Authentication broker
---------------------

.. py:class:: AuthnBroker(allow_exact_level_matching: bool = False)

   Registers authentication methods and selects them by authentication context.
   ``Comparison="exact"`` is a literal class-ref match (saml-core-2.0-os
   3.3.2.2.1); ``allow_exact_level_matching=True`` restores pysaml2's looser
   behaviour, where any method at the same security level counts. Every listed
   class ref is an alternative for every comparison; the result is in the
   request's order, not sorted by strength (``check_request`` sorts its
   ``"authenticate"`` methods strongest first).

   .. py:method:: is_empty() -> bool

      Whether no method is registered. With an empty broker an ``exact``
      request is left to the response-time check (an inline method is accepted
      if its class ref matches literally); ``minimum``, ``maximum`` and
      ``better`` need the broker's strength ordering and are denied before login.

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

.. py:class:: AssertionStore

   Protocol for a persistent store of issued assertions, passed as
   ``ResponseEngine(assertions=...)`` (the built-in :class:`InMemoryAssertionStore`
   is lost on restart). Assertions cross as :class:`pygamlastan.core.Assertion`.
   Any exception is a backend failure and surfaces as
   :class:`pygamlastan.SamlStoreError`; never return ``None`` or an empty list
   for a backend that could not answer. If the store cannot record an assertion,
   ``create_authn_response`` raises and nothing is issued.

   .. py:method:: store_assertion(assertion: pygamlastan.core.Assertion) -> None
   .. py:method:: get_assertion(assertion_id: str) -> pygamlastan.core.Assertion | None
   .. py:method:: assertions_for_subject(name_id_value: str) -> Iterable[pygamlastan.core.Assertion]
   .. py:method:: remove_assertion(assertion_id: str) -> None

   The engine itself only calls ``store_assertion``. The other three serve
   back-channel queries and your own logout code: pysaml2's
   ``remove_authn_statements(name_id)`` is ``assertions_for_subject`` followed by
   ``remove_assertion``.

.. py:class:: InMemoryAssertionStore()

   Retains issued assertions to answer later queries.

   .. py:method:: store_assertion(assertion: pygamlastan.core.Assertion) -> None
   .. py:method:: get_assertion(assertion_id: str) -> pygamlastan.core.Assertion | None
   .. py:method:: assertions_for_subject(name_id_value: str) -> list[pygamlastan.core.Assertion]
   .. py:method:: remove_assertion(assertion_id: str) -> None

Identity database
-----------------

.. py:class:: IdentDb(idp_entity_id: str, store: IdentityStore | None = None, domain: str | None = None, persist_transient: bool = False, verify_store: bool = True)

   The IdP identity database (pysaml2 ``IdentDB``): the bidirectional mapping
   between local user ids and the NameIDs issued to relying parties, NameID
   generation honoring an incoming ``NameIDPolicy``, and the server side of the
   ManageNameID / NameIDMapping profiles.

   ``idp_entity_id`` is the default NameQualifier. With ``store=None`` the
   database is in-memory; pass an object implementing the record-shaped
   ``IdentityStore`` protocol to back it with SQL/Mongo. ``domain`` is appended to email-format NameIDs.

   Transient NameIDs are not stored by default: they are one-time-use, and the
   default per-SP format is transient, so storing every one would add a record
   per response. The consequence is that :meth:`find_local_id` cannot resolve a
   transient NameID, which a back-channel (SOAP) LogoutRequest carrying one
   needs. Set ``persist_transient=True`` to store them; the backend must then
   expire them itself, since the record protocol has no expiry.

   A caller-supplied ``store`` is checked, not trusted (see
   :class:`IdentityStore`); ``verify_store=False`` turns that off for a store you
   fully trust. The built-in in-memory store is never checked.

   .. py:method:: store(user_id: str, name_id: pygamlastan.core.NameId) -> None

      Associate a NameID with a local user (maintains both directions).

   .. py:method:: find_local_id(name_id: pygamlastan.core.NameId) -> str | None

      The local user a NameID was issued to, if known.

   .. py:method:: find_nameid(user_id: str, format: str | None = None, sp_name_qualifier: str | None = None, name_qualifier: str | None = None, sp_provided_id: str | None = None) -> list[pygamlastan.core.NameId]

      The user's NameIDs that match every filter that is set (pysaml2
      ``find_nameid``). An unset filter matches anything. A set one must equal
      the record's value exactly, so a record that lacks the field does not match
      (unlike :meth:`match_local_id`, where ``None`` means "the record has no
      such qualifier"). Order is unspecified.

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

   Protocol for a pluggable :class:`IdentDb` backend: one record per
   (user, NameID). The backend must enforce two unique constraints: the NameID
   value is unique across all records, and among durable records (every format
   except transient) ``(user, sp_name_qualifier, name_qualifier, format)`` is
   unique. A record with no format counts as ``unspecified``.

   Run :func:`check_store_conformance` against your backend before relying on it.

   :class:`IdentDb` does not trust what the backend returns (gamlastan's
   ``IdentDb`` does this for every backend, Rust or Python). A record from
   ``find_durable`` or ``get_or_insert_durable`` must be the durable slot that was
   asked for, and ``user_for(record.value)`` must name the same user; otherwise
   :class:`pygamlastan.SamlStoreError` is raised and the record is not used. A
   query that forgot the user in its filter, a wrong index or a stale cache would
   otherwise hand one user another user's persistent NameID. ``find_local_id``
   is confirmed the same way: the owner ``user_for`` names must hold that value
   in its own ``for_user`` listing.

   This holds whether or not you define the optional ``find`` and
   ``find_durable``: without them the binding filters ``for_user`` and the
   records it selects are checked, at the cost of one ``user_for`` call per
   record. ``IdentDb.name_ids_for`` checks every record it returns. So
   ``user_for`` must see the backend's own writes (read-your-writes), not a
   lagging replica; read from the primary.

   Raise :class:`pygamlastan.NameIdValueTaken` or
   :class:`pygamlastan.NameIdDurableExists` for a conflict. Any other exception
   is a backend failure and surfaces as :class:`pygamlastan.SamlStoreError`;
   never return "no record" when the backend could not answer.

   .. py:method:: for_user(user_id: str) -> Iterable[pygamlastan.core.NameId]
   .. py:method:: user_for(value: str) -> str | None
   .. py:method:: get_or_insert_durable(user_id: str, candidate: pygamlastan.core.NameId) -> pygamlastan.core.NameId
   .. py:method:: insert(user_id: str, name_id: pygamlastan.core.NameId) -> None
   .. py:method:: replace(user_id: str, name_id: pygamlastan.core.NameId) -> None

      Update a record in place for its owner. It must never move a record to
      another user: raise :class:`pygamlastan.NameIdValueTaken` for a value
      another user holds, since a reassigned value would let the new user log in
      as the old one at every SP that has seen it.

   .. py:method:: remove(value: str) -> None
   .. py:method:: remove_all(user_id: str) -> None

   Optionally ``find_durable(user_id, sp_name_qualifier, name_qualifier, format)
   -> NameId | None`` pushes the durable lookup down to an index, and
   ``find(user_id, format, sp_name_qualifier, name_qualifier, sp_provided_id)
   -> Iterable[NameId]`` pushes :meth:`IdentDb.find_nameid` down to a query
   (``None`` means unconstrained). Each record ``find`` returns must satisfy the
   filter and belong to ``user_id``, or :class:`pygamlastan.SamlStoreError` is
   raised; the conformance suite checks it too. Without them the binding filters
   ``for_user`` itself.

Checking a store backend
------------------------

The record-shaped store has no default write methods: a non-atomic default would
silently leave a race open on a multi-instance IdP. The atomicity comes from two
unique constraints the backend enforces, and a missing unique index compiles
fine and only misbehaves under load (two workers issuing different "stable"
identifiers to one user). The conformance suite checks that a backend honours
the contract the response engine relies on.

.. code-block:: python

   def new_store():
       # a fresh, EMPTY store: a new collection/table, or one that was cleared
       coll = db[f"ident_test_{uuid4().hex}"]
       return MongoIdentityStore(coll)

   def test_my_backend_honours_the_contract():
       idp.check_store_conformance(new_store)   # raises on the first violation

.. py:function:: check_store_conformance(new_store: Callable[[], IdentityStore], threads: int = 16) -> None

   Run every check. ``new_store`` is called with no arguments and must return a
   fresh, empty store each time; each check gets its own. Raises
   :class:`pygamlastan.StoreConformanceError` on the first violation, with the
   failing check in ``.check`` and what it found in ``.message``. A factory that
   raises is a setup error and propagates as it was.

   Run it against a real instance of the backend, with its real indexes. It
   releases the GIL while it runs, because the concurrent checks call your store
   from several threads. A store that serialises every call (one global lock)
   can pass the concurrent checks without having the constraint, and a race
   between separate processes is not detected.

.. py:function:: check_store_conformance_one(name: str, new_store: Callable[[], IdentityStore], threads: int = 16) -> None

   Run the single check ``name`` (one of ``STORE_CONFORMANCE_CHECKS``), to see
   which constraint a backend is missing.

.. py:data:: STORE_CONFORMANCE_CHECKS

   The check names, in the order they run: value uniqueness, lookups, durable
   get-or-insert, the durable constraint on every write path (``insert`` and
   ``replace`` as well as ``get_or_insert_durable``), exact durable lookups,
   filtered lookups, ``replace`` semantics (including refusing another user's
   value), scoped removal, and two concurrent checks.

Attribute-release policy
------------------------

The release policy (pysaml2 ``Policy``) decides which attributes - and which
values - the IdP releases to each SP. Per-knob resolution is: the SP-specific
entry, then the SP's registration-authority entry (when recorded), then the
``"default"`` entry, then a built-in default.

.. py:class:: ReleasePolicy(default: PolicyEntry | None = None, converters: pygamlastan.attribute_map.AttributeConverterSet | None = None)

   ``converters`` resolves attribute names to local names when matching entity
   categories, requested attributes and restrictions. The shipped maps are used
   by default; pass your own (copied in) for a deployment whose maps differ, such
   as one loaded from a pysaml2 ``attribute_map_dir``.

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

.. py:class:: PolicyEntry(nameid_format: str | None = None, name_form: str | None = None, lifetime_seconds: int | None = None, sign: SignTargets | None = None, fail_on_missing_requested: bool | None = None, entity_categories: list[str] | None = None, owned_entity_categories: list[EntityCategoryPolicy] | None = None, attribute_restrictions: list[tuple[str, list[str] | None]] | None = None, session_lifetime_seconds: int | None = None, supported_nameid_formats: list[str] | None = None, signing_preference: pygamlastan.crypto.SigningPreference | None = None, deny_unconfigured_release: bool | None = None)

   One policy entry. ``entity_categories`` names shipped policies (e.g.
   ``["swamid"]``); ``owned_entity_categories`` supplies developer-built ones;
   the two are merged. ``attribute_restrictions`` maps a local attribute name to
   a list of value patterns (anchored, ``re.match`` semantics) or ``None`` for
   all values; attributes not named are not released. Raises
   :class:`pygamlastan.SamlPolicyError` if a pattern fails to compile.

   * ``session_lifetime_seconds``: the SSO session's absolute lifetime
     (``AuthnStatement/@SessionNotOnOrAfter``), separate from the assertion
     ``lifetime_seconds``; falls back to the assertion lifetime when unset.
   * ``supported_nameid_formats``: the NameID formats this IdP will issue to the
     SP; a requested ``NameIDPolicy/@Format`` outside the set (and the SP's own
     default) is denied with ``Denial.INVALID_NAME_ID_POLICY`` before anything is
     stored. **Unset, any requested format is accepted**, as in pysaml2, and
     every non-transient one is stored, so an SP that sends invented format
     strings gets one record per string. Set it in production;
     ``ISSUABLE_NAMEID_FORMATS`` is a starting set. A format longer than
     ``MAX_NAMEID_FORMAT_LEN`` (256 bytes) and ``nameid-format:encrypted`` are
     refused whatever is configured.
   * ``signing_preference``: a :class:`pygamlastan.crypto.SigningPreference`.
   * ``deny_unconfigured_release``: with ``True``, an SP that no attribute rule
     covers (no entity categories, no attributes requested in its metadata, no
     restrictions) is released nothing. **By default it is released every
     attribute the application supplied**, as in pysaml2: the policy only
     narrows. Set it on the ``"default"`` entry to fail closed everywhere, and
     ``False`` on one SP's entry to override.

.. py:class:: SignTargets(response: bool = False, assertion: bool = False, on_demand: bool = False)

   Which messages the IdP signs for an SP. ``on_demand`` signs the assertion
   when the SP's metadata sets ``WantAssertionsSigned``.

   .. py:method:: resolve(sp_wants_assertions_signed: bool) -> ResolvedSignTargets

.. py:class:: ResolvedSignTargets

   The concrete decision: ``sign_response`` / ``sign_assertion``.

Response engine
---------------

The orchestrator (gamlastan ``idp::orchestrator``) composes the pieces above
into the SAML Web Browser SSO response flow. The application supplies identity
facts; the engine decides what the request requires, derives the NameID,
releases attributes and signs the response.

.. code-block:: python

   engine = idp.ResponseEngine(
       IDP, policy, idents, broker, signer, cert_der_b64)
   req = xml.parse_authn_request(authn_request_xml)
   params = idp.ResponseParams(
       profiles.process_authn_request(req, sp_entity, request_signature_verified),
       sp_entity)

   disposition = engine.check_request(params, session)   # session or None
   if disposition.kind == "deny":
       return engine.create_denial_response(params, disposition.denial)
   if disposition.kind == "authenticate":
       ...  # log the user in, then build `subject`
   outcome = engine.create_authn_response(params, subject)
   deliver(outcome.xml)   # an issued response or a signed denial

.. py:class:: ResponseEngine(idp_entity_id, policy, idents, broker, signer, cert_der_b64, assertions=None, release="policy")

   ``policy`` is a :class:`ReleasePolicy`, ``idents`` an :class:`IdentDb`,
   ``broker`` an :class:`AuthnBroker`, ``signer`` a
   :class:`pygamlastan.crypto.SamlSigner`, ``cert_der_b64`` the signing
   certificate as base64 DER (the body of the PEM, no header lines), and
   ``assertions`` an optional :class:`InMemoryAssertionStore`, or any object
   implementing :class:`AssertionStore`, so back-channel queries and logout can
   find the assertions it issued. ``release="policy"`` filters attributes through the
   policy; ``release="pass_through"`` releases what the application supplied,
   for a proxy whose attributes were filtered upstream. The engine holds
   references, so later changes to those objects are seen by the next call. Make
   them between calls: the policy, identity database, broker and signer are
   borrowed for the whole of a call, including every callback into your stores,
   so mutating one from inside a store callback raises ``RuntimeError: Already
   borrowed`` (reported as :class:`pygamlastan.SamlStoreError`).

   .. py:method:: check_request(params: ResponseParams, session: EstablishedSession | None = None) -> Disposition

      Decide what to do, without any I/O: the ForceAuthn x IsPassive x
      RequestedAuthnContext matrix, weighed against the browser's session.
      Call it before authenticating anyone and act on ``"deny"`` without a
      login. A request naming only ``AuthnContextDeclRef``\ s is denied: a
      declaration cannot be shown to be met.

   .. py:method:: create_authn_response(params: ResponseParams, subject: AuthenticatedSubject) -> ResponseOutcome

      Assemble and sign the response. A request that cannot be satisfied (an
      unsupported or overlong NameID format, a session that expired while the
      user authenticated, a method that does not satisfy the requested context,
      required attributes that were not released) is a signed denial in the
      outcome. Raises :class:`pygamlastan.SamlStoreError` if the identity or
      assertion store failed, and :class:`pygamlastan.SamlProfileError` for a
      configuration fault (an unknown ``AuthnMethodRef.broker`` reference, or
      parameters for a different SP).

   .. py:method:: create_denial_response(params: ResponseParams, denial: Denial) -> DeniedResponse

      A signed protocol error. The envelope is always signed, whatever the
      per-SP signing targets.

.. py:class:: ResponseParams(processed: pygamlastan.profiles.ProcessedAuthnRequest, entity: pygamlastan.metadata.EntityDescriptor)

   A processed request bound to the trusted metadata of the SP it came from.
   The SAML 2.0 SP role is taken from ``entity``, so the request, the role and
   the entity cannot come from different SPs.

.. py:class:: AuthenticatedSubject(subject_id, attributes, authn_method, authn_instant=None, session_index=None)

   The authenticated subject: its identifier, raw (unfiltered) attributes, the
   method that ran, when, and the session index. ``authn_instant`` must be
   timezone-aware; ``None`` means now. When reusing a session, pass the
   session's own instant.

.. py:class:: AuthnMethodRef

   ``AuthnMethodRef.inline(class_ref, authn_authority=None)`` gives a class ref
   directly (a proxy, or a login flow outside the broker). **The engine verifies
   nothing about it**: for ``Comparison="exact"`` an inline class ref satisfies
   the request by matching the request, so an application that builds it from
   request data signs an assertion claiming a context that was never
   established. Build it from what your login flow did (a constant, or the
   upstream IdP's reported context in a proxy), never from the ``AuthnRequest``;
   ``AuthnMethodRef.broker(reference)`` names a method registered with
   :meth:`AuthnBroker.add`. A reference the broker does not know is an error,
   never a class ref taken from the string.

.. py:class:: EstablishedSession(subject_id, authn_method, authn_instant, session_index)

   A session the application already has for the browser.

.. py:class:: Disposition

   ``kind`` is ``"reuse_session"`` (``session`` is set), ``"authenticate"``
   (``methods`` are the registered methods that satisfy the request, strongest
   first; empty when the broker has none) or ``"deny"`` (``denial`` says why).

.. py:class:: Denial

   ``NO_PASSIVE``, ``NO_AUTHN_CONTEXT``, ``INVALID_NAME_ID_POLICY``,
   ``NAME_ID_CREATION_NOT_ALLOWED``, ``MISSING_REQUIRED_ATTRIBUTES``,
   ``INVALID_ATTRIBUTE_CONSUMING_SERVICE_INDEX``, ``AUTHN_FAILED`` and
   ``CANCELLED`` (the last two for a failed or user-cancelled login, which the
   application reports itself). A closed set with a fixed SAML status: nothing
   the SP sent reaches the status message.

.. py:class:: ResponseOutcome

   ``is_issued``; ``issued`` (an :class:`IssuedResponse`) or ``denied`` (a
   :class:`DeniedResponse`) with ``denial``; and ``xml`` for whichever it is.

.. py:class:: IssuedResponse

   ``xml``, ``response_id``, ``assertion_id``, ``name_id``, ``session_index``,
   ``not_on_or_after`` and ``released_attribute_names`` (names only, never
   values): the identifiers an audit log needs.

.. py:class:: DeniedResponse

   ``xml`` and ``response_id``. A denial has no assertion, subject or session.

What the engine does not do, and the application must:

* enforce ``Scoping`` (``ProxyCount``, ``IDPList``) if it is a proxy: read it
  from :attr:`pygamlastan.core.AuthnRequest.scoping`;
* compare a requested ``Subject`` with the authenticated user, or refuse
  requests that name one: see
  :meth:`pygamlastan.core.AuthnRequest.requested_subject_name_id` and
  ``has_requested_subject``.

Several defaults follow pysaml2 and are permissive; review them for a
production IdP. With no rule covering an SP (entity categories, attributes
requested in its metadata, restrictions) every attribute the application
supplies is released: set ``deny_unconfigured_release``. Any requested NameID
format is accepted and every non-transient one is stored: set
``supported_nameid_formats``. The default signing policy signs the assertion.
With an HSM-backed signer, list only the token's signature method in a
``SigningPreference``.

Signing algorithms
------------------

.. py:class:: pygamlastan.crypto.SignatureMethod
.. py:class:: pygamlastan.crypto.DigestMethod

   Closed sets of strong algorithms: ``RSA_SHA256``/``384``/``512``,
   ``ECDSA_SHA256``/``384``/``512`` and ``SHA256``/``384``/``512``. SHA-1, MD5
   and the like are not representable, so neither configuration nor an SP's
   metadata can select them. ``.uri`` is the XML-DSig URI and
   ``from_uri(uri)`` returns ``None`` for anything else.

.. py:class:: pygamlastan.crypto.SigningPreference(signature_methods=None, digest_methods=None)

   An ordered preference, set per SP with ``PolicyEntry(signing_preference=...)``.
   For each kind the first entry the SP also advertises in its metadata wins;
   if it advertises none (or nothing), the first entry wins; an empty list
   leaves the signer's default. The advertisement is untrusted: it only chooses
   among your entries. Signatures are matched against ``alg:SigningMethod`` and
   digests against ``alg:DigestMethod``, separately.

   With an HSM-backed signer list **only the token's own signature method**: a
   response that resolves to another one fails with an error, denials included,
   for the SPs that resolve to it, when it is signed (not at startup).

   .. py:method:: resolve(sp_signature_methods=None, sp_digest_methods=None) -> SigningAlgorithms

      The algorithms chosen for an SP advertising the given URIs.

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
