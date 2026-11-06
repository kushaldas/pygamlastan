Security guide
==============

SAML is a security protocol whose entire value depends on getting a handful of
checks exactly right. ``pygamlastan`` is a thin binding: the cryptography and
the validation suite (the 32-item Section 7.2 checklist plus response-envelope
checks 33-34 and the per-assertion age check 35) live upstream in ``gamlastan``
/ ``bergshamra`` / ``kryptering``. This guide describes the security properties the **binding**
preserves, the safe entry points, and the footguns the API deliberately leaves
reachable so that you can integrate without recreating a classic SAML CVE.

Read this before wiring pygamlastan into an authentication flow.

.. contents::
   :local:
   :depth: 1


Signature trust is the whole game
---------------------------------

A SAML Response is only meaningful if its signature was **cryptographically
verified against a trusted IdP key** *and* that verification is bound to the
exact assertion you then trust. Every real-world SAML break — signature
exclusion, signature wrapping (XSW), comment splicing — is a failure of that
binding, not of the underlying crypto.

pygamlastan gives you two ways to process a response. **One is safe by
construction; the other trusts you to do the binding yourself.**

``process_response_verified`` — the safe entry point (use this)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:func:`pygamlastan.profiles.process_response_verified` takes the **raw response
XML** and a :class:`pygamlastan.crypto.SamlVerifier` built from the trusted IdP
certificate. It performs the XML-DSig verification *internally, over the exact
bytes it then parses and validates*, and feeds only the cryptographically
verified reference IDs into the validation suite. There is no way for the
"verified" set to drift from the bytes you actually trust.

.. code-block:: python

   from pygamlastan import crypto, security, profiles

   verifier = crypto.SamlVerifier.from_cert(idp_cert_pem)   # trust anchor + verify key

   result = profiles.process_response_verified(
       response_xml,                       # raw bytes as received at the ACS
       verifier,
       security.SecurityConfig(),          # production defaults
       sp_entity_id="https://sp.example.org/sp",
       acs_url="https://sp.example.org/acs",
       expected_idp_entity_id="https://idp.example.org",
       expected_request_id="_req1",
       replay_cache=security.InMemoryReplayCache(),
   )
   identity = result.name_id

Prefer this entry point in every SP integration. It is the one the
``examples/django-sp`` app uses.

``process_response`` / ``validate_response`` — trust is caller-supplied
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:func:`pygamlastan.profiles.process_response` and
:func:`pygamlastan.security.validate_response` take a **parsed** ``Response``
plus two caller-supplied trust inputs:

* ``response_signature_verified`` — a plain bool, and
* ``verified_signed_ids`` — the element IDs you *claim* were cryptographically
  verified.

These functions **do not verify any signature themselves.** They decide whether
the signed-assertion / signed-response requirements are satisfied entirely from
what you pass in.

.. danger::

   If you pass ``response_signature_verified=True`` or a hand-built
   ``verified_signed_ids`` **without actually verifying**, or you verify the
   *wrong* document, every signature-dependent check passes vacuously — a full
   **authentication bypass / assertion forgery**. This is exactly the class of
   bug behind real SAML CVEs.

If you must use the lower-level path (e.g. you verify with your own crypto), the
``verified_signed_ids`` you pass **must** come from a real verification of the
same bytes:

.. code-block:: python

   verify_results = verifier.verify_all_enveloped(response_xml)   # real XML-DSig checks
   if not verify_results or any(not result for result in verify_results):
       raise ValueError("SAML response signature verification failed")
   verified_signed_ids = [
       signed_id
       for verify_result in verify_results
       for signed_id in verify_result.signed_reference_ids()
   ]
   parsed = xml.parse_response(response_xml)                     # same bytes
   result = profiles.process_response(
       parsed, security.SecurityConfig(), sp_entity_id, acs_url, idp_entity_id,
       verified_signed_ids=verified_signed_ids,               # from the verifier, not hand-built
       replay_cache=security.InMemoryReplayCache(),
   )

When in doubt, use ``process_response_verified`` and let the binding do the
binding.


Verifier policy knobs
---------------------

:class:`pygamlastan.crypto.SamlVerifier` exposes the XML-DSig hardening knobs
from gamlastan, including the 0.9 algorithm allowlist. The defaults are the
SAML-safe values; the example below sets them explicitly so an audit can see
the intended policy:

.. code-block:: python

   from pygamlastan import crypto

   verifier = crypto.SamlVerifier.from_cert(idp_cert_pem)

   # RSA/ECDSA SHA-256/384/512 signatures and SHA-256/384/512 digests.
   verifier.set_algorithm_policy(crypto.AlgorithmPolicy())

   # Keep X.509 NotBefore/NotAfter enforcement enabled.
   verifier.set_skip_time_checks(False)

   # Trust only keys/certificates you configured, never attacker-supplied KeyInfo.
   verifier.set_trusted_keys_only(True)

   # Enforce XML Signature Wrapping reference-position checks.
   verifier.set_strict_verification(True)

   # Reject HMAC truncation below CVE-2009-0217's 160-bit floor.
   verifier.set_hmac_min_out_len(160)

   # Require every signed reference digest to be checked locally.
   verifier.set_require_reference_digests(True)

   # Do not let raw inline KeyValue/DEREncodedKeyValue bypass trust anchors.
   verifier.set_allow_raw_inline_keyinfo_with_trust_anchors(False)

   # SAML federation signatures use asymmetric keys, not shared-secret HMAC.
   verifier.set_reject_hmac_signatures(True)

.. note::

   Using the ``compat.saml2`` shim instead of this native API directly? The SP
   settings ``service.sp.allowed_signature_algorithms`` /
   ``allowed_digest_algorithms`` (see :doc:`pysaml2_compat`) apply the same
   allowlist widening without constructing a ``SamlVerifier`` by hand. It is
   an SP-wide setting -- it applies to every IdP the SP verifies against, not
   just the one that needs the legacy algorithm.

The unsafe directions are guarded: disabling trusted-key-only mode, non-strict
verification, reference-digest enforcement, X.509 time checks, or the HMAC
minimum raises unless the matching ``unsafe_*`` argument is explicit. Enabling
raw inline KeyInfo with configured trust anchors is guarded the same way.

For a document with more than one signature, use
:meth:`pygamlastan.crypto.SamlVerifier.verify_all_enveloped` to inspect every
signature:

.. code-block:: python

   results = verifier.verify_all_enveloped(response_xml)
   if not results or any(not result for result in results):
       raise ValueError("SAML response signature verification failed")
   signed_ids = [
       signed_id
       for result in results
       for signed_id in result.signed_reference_ids()
   ]

``process_response_verified`` already does this internally. You only need this
manual collection when you deliberately use the lower-level
``process_response`` / ``validate_response`` APIs.


XML input hardening (XXE, billion-laughs, deep nesting)
-------------------------------------------------------

Every parse entry point in pygamlastan handles attacker-controlled XML, so they
all go through gamlastan's hardened ``parse_secure`` path — there is **no API
that exposes the raw parser**, so this cannot be bypassed from Python. Two
defenses are applied before any SAML-level processing:

* **DTD / ``<!DOCTYPE>`` rejection.** Any document carrying a DTD is rejected
  with :class:`pygamlastan.SamlXmlError`. Legitimate SAML never uses a DTD, so
  this categorically removes **XXE / external-entity / entity-smuggling**: no
  external entity is resolved and no internal entity is expanded into a parsed
  SAML tree.

* **Fail-closed resource limits** (uppsala 0.10): element nesting depth (128),
  entity-expansion byte budget (1 MiB), and entity nesting depth (256). These
  bound **billion-laughs / quadratic-blowup** amplification and **deep-nesting
  stack exhaustion**. Exceeding a limit raises :class:`pygamlastan.SamlXmlError`.

This protection covers :doc:`../api/xml` (responses, requests, assertions,
logout messages), :doc:`../api/metadata` (remote/published metadata), and the
internal parse inside ``process_response_verified``. See :ref:`xml-hardening`
for a code example.


Authentication freshness (``authn_instant``)
--------------------------------------------

SAML distinguishes *when a response was generated* (``IssueInstant``) from *when
the principal actually authenticated* (``AuthnStatement/@AuthnInstant``). When an
IdP reuses an existing SSO session instead of re-prompting, the authentication
happened **earlier** than the response.

:func:`pygamlastan.profiles.create_response` (and ``create_unsolicited_response``)
keep these separate:

* ``now`` — the issue instant (defaults to the current wall clock).
* ``authn_instant`` — the real authentication time (defaults to ``now``).

.. code-block:: python

   # Reused SSO session: report the real login time, not "now".
   resp = profiles.create_response(options, name_id, authn_instant=user_last_login)

   # Fresh login: omit authn_instant; both instants collapse to now.
   resp = profiles.create_response(options, name_id)

.. warning::

   Collapsing both instants to "now" for a reused session **over-reports
   authentication freshness** to SPs that enforce it via ``ForceAuthn``,
   ``RequestedAuthnContext``, or a max-age policy — a freshness-spoofing
   weakness. Pass the true ``authn_instant`` (e.g. Django's ``user.last_login``)
   whenever a session may be reused. ``examples/django-idp`` does this.


Replay protection and persistent-NameID safety
-----------------------------------------------

* **Replay cache.** A replay cache rejects an assertion ID that has already been
  seen. It is **required by default** — ``process_response`` /
  ``process_response_verified`` refuse to run without one rather than silently
  skipping replay protection. The in-memory cache is single-process; back it
  with a shared store (database/Redis) for multi-worker deployments. The Python
  adapter **fails closed**: if your ``check_and_insert`` raises, the ID is
  treated as a replay. See :doc:`validation`.

* **Persistent-ID store.** Persistent-NameID uniqueness (E78) is **off by
  default** and opt-in: when you enable it and a response carries a persistent
  NameID, both a persistent-ID store **and** a ``persistent_id_principal`` are
  required so NameID **reassignment** (one identifier re-pointed at a different
  subject) is detected. The principal is your local account id, resolved
  independently of the asserted NameID; gamlastan will not enforce the invariant
  from the SAML input alone. This adapter also fails closed: a Python-side error
  is treated as a conflict.

* The ``unsafe_no_replay_cache`` / ``unsafe_no_persistent_id_store`` flags only
  skip the binding's *precondition* checks; they do **not** disable enforcement.
  gamlastan now fails the replay check (20) closed when no cache is configured,
  so ``unsafe_no_replay_cache`` cannot buy a valid result - it merely moves the
  failure into the validation output. The ``unsafe_`` prefix is a deliberate
  signpost: do not set them in production.


Encrypted assertions
---------------------

The generic ``process_response`` cannot decrypt or prove the provenance of an
``EncryptedAssertion``, so it **rejects** ``require_encrypted_assertions`` and
refuses opaque encrypted-only responses rather than pretending to validate them.
Decrypt first (see :doc:`../api/crypto`) and validate the decrypted assertion,
or use a profile path that handles decryption.


Untrusted metadata: display fields and URLs
-------------------------------------------

Metadata is **attacker-influenced input**. SAML metadata comes from federation
aggregates and MDQ servers, and a single entry is controlled by whoever operates
that SP or IdP - not by you. pygamlastan *parses* metadata; it does **not**
sanitize the human-facing strings and URLs inside it for safe display. The
parser rejects DTDs and bounds resource use (see the XML-hardening section
above), but the **values** it returns are copied verbatim from the document.

This matters most for the :class:`~pygamlastan.metadata.UiInfo` /
:class:`~pygamlastan.metadata.UiLogo` data (``mdui:UIInfo``) an IdP reads to show
an SP's name and logo on a consent screen, via
:meth:`EntityDescriptor.ui_info() <pygamlastan.metadata.EntityDescriptor.ui_info>`.

.. important::

   Treat every ``UiInfo`` / ``UiLogo`` string as untrusted, attacker-controlled
   data. Two concrete risks:

   * **Stored XSS.** ``display_names``, ``descriptions``, and ``keywords`` values
     are raw text from the SP's metadata. If you render them into HTML without
     **output-encoding** them, a hostile SP can inject script into your consent
     page. Always HTML-escape these before display (most template engines do this
     by default - do not bypass it with "safe"/"raw" markers here).
   * **Dangerous URL schemes.** ``information_urls``, ``privacy_statement_urls``,
     and :attr:`UiLogo.url <pygamlastan.metadata.UiLogo.url>` are **not**
     scheme-checked. A value may be ``javascript:...`` or a hostile ``data:``
     URI. Before emitting one as an ``href`` or ``<img src>``, validate it
     against an explicit allowlist - typically ``https:`` only (and ``data:``
     only if you intentionally inline images).

.. code-block:: python

   from urllib.parse import urlparse

   def safe_logo_url(logo):
       # Allow only https logos; reject javascript:/data:/everything else.
       if urlparse(logo.url).scheme == "https":
           return logo.url
       return None  # fall back to a default icon

   ui = sp_metadata.ui_info("sp")
   if ui and ui.display_names:
       # `name` must still be HTML-escaped by your template on render.
       name = ui.display_names[0][1]

The same "parsed, not vetted" rule applies to the other metadata accessors:
:meth:`~pygamlastan.metadata.EntityDescriptor.entity_categories`,
:meth:`~pygamlastan.metadata.EntityDescriptor.entity_attribute_values`,
:meth:`~pygamlastan.metadata.EntityDescriptor.supported_algorithms`, and
:attr:`~pygamlastan.metadata.EntityDescriptor.registration_authority` are signals
from the SP's metadata. Use them to *make decisions* (which attributes to
release, which algorithm to use), but if you ever echo them into a UI or log,
output-encode them too. The trustworthiness of any of these depends entirely on
having fetched the metadata over **signature-verified** MDQ or from a vetted
local file - an unsigned metadata feed lets an attacker set all of it.

.. note::

   Attribute-release decisions key on metadata too:
   :meth:`EntityDescriptor.requested_attributes()
   <pygamlastan.metadata.EntityDescriptor.requested_attributes>` and the
   entity-category URIs drive what
   :meth:`ReleasePolicy.filter() <pygamlastan.idp.ReleasePolicy.filter>`
   releases. A hostile or spoofed SP entry could request more than it should, so
   the release policy is your privacy boundary - see :doc:`idp_integration`.


Decisions and limits of the IdP engine and its backends
-------------------------------------------------------

These are choices, not oversights. Each is stated with its reason so a reviewer
(or a later change) can see what is decided, what is the application's job, and
what would be needed to change it.

``AuthnMethodRef.inline`` is the application's own claim
   The engine verifies nothing about it. For ``Comparison="exact"`` an inline
   class ref satisfies the request by *matching the request*, so an application
   that builds it from the ``AuthnRequest`` signs an assertion claiming an
   authentication context that was never established. Only the login flow knows
   which method ran, so the engine cannot check it. Build it from a constant or
   from the upstream IdP's reported context, never from request data.
   ``AuthnMethodRef.broker`` is held to the broker's registration but is still
   your claim about which method ran. A ``ResponseEngine`` flag that rejects
   inline refs outright is possible, and is not implemented.

The EPTID cache must be private to one IdP and one secret
   ``Eptid(store=...)`` remembers issued values so that rotating the secret (or
   the digest) cannot change what an SP already knows. Its shape check rejects
   another IdP's or SP's value and a wrong key. It **cannot** tell two
   right-shaped values apart: a cache shared with another deployment that uses
   the same IdP entity ID, a backup restored from one, and a forged value are
   accepted, and a flush is a miss, after which a changed secret or digest issues
   a different identifier. The cache key deliberately does **not** include the
   secret: a key that changed with the secret would turn every rotation into a
   miss, which is the failure the cache exists to prevent. So keep the namespace
   private (one cache per IdP and secret: blue/green, staging and merged tenants
   must not share one), never let it evict or expire, and run
   :func:`~pygamlastan.idp.check_kv_conformance` against it.

Metadata accessors read roles, not endpoints
   An entity can carry a legacy role beside a SAML 2.0 one. The
   :class:`~pygamlastan.metadata.EntityDescriptor` accessors read only roles that
   declare SAML 2.0 by default, so a key published only for a legacy role is never
   offered for a SAML 2.0 message. A role that declares several protocols is read
   as a whole, so still choose endpoints by binding. Metadata that fails to mark
   its SAML 2.0 role as such yields nothing (it fails closed). ``protocol=None``
   reads every role, for inspection tools, and must not feed a trust decision.
   Document-level checks (``SPConfig`` loading a shared aggregate) read every
   role, so one legacy-only IdP does not discard the others; such an IdP fails
   where it is used, with a message that names the cause.

Backends are checked, not trusted, and that has requirements
   Every record a store returns is verified against ``user_for``, the durable
   slot and the filter, so a backend that forgot its ``WHERE user_id`` raises
   instead of handing over another user's NameID. That needs ``user_for`` to see
   the store's own writes (read from the primary, not a lagging replica) and
   backend-enforced unique constraints. ``verify_store=False`` turns the checks
   off, warns, and is for a store you fully trust. Run
   :func:`~pygamlastan.idp.check_store_conformance`,
   :func:`~pygamlastan.idp.check_kv_conformance` and
   :func:`~pygamlastan.idp.check_assertion_store_conformance` against a **real**
   instance with its real indexes: a store that serialises every call can pass the
   concurrent checks without holding the constraint, and a race between separate
   processes is not detected.

Query responders are not bound
   gamlastan's ``get_authn_statements`` and ``create_assertion_id_request_response``
   check that an assertion belongs to the subject or ID asked about, but they are
   not exposed to Python. An author building an AuthnQuery or AssertionIDRequest
   responder on an ``AssertionStore`` must make the same checks, and must decide
   whether the *requester* may ask: the subject check binds the answer to the
   NameID value, not to who is asking.

Footguns the API leaves reachable (and why)
-------------------------------------------

These exist for tests, examples, and advanced integrators. Each is named so it
is obvious in a code review.

``SecurityConfig.permissive()``
   Relaxes signature and other requirements. Constructing it emits a
   ``UserWarning``. **Never use it in production** — it exists so examples and
   tests can run without real signatures. Use :class:`SecurityConfig` (production
   defaults) or :meth:`SecurityConfig.strict` instead.

The ``now`` parameter
   ``process_response*`` and ``validate_response`` accept a ``now`` override for
   deterministic tests. In production, omit it so the real wall clock drives the
   validity-window checks — a caller-pinned ``now`` could keep an expired
   assertion inside its window.

``verified_signed_ids`` / ``response_signature_verified``
   The trust-coupling inputs described above. Only ever populate
   ``verified_signed_ids`` from a real :class:`~pygamlastan.crypto.SamlVerifier`
   result over the same bytes — or avoid them entirely by using
   ``process_response_verified``.

Verifier downgrade methods
   Methods such as ``set_trusted_keys_only(False)``,
   ``set_strict_verification(False)``,
   ``set_require_reference_digests(False)``,
   ``set_allow_raw_inline_keyinfo_with_trust_anchors(True)``,
   ``set_hmac_min_out_len(0)``, and ``set_skip_time_checks(True)`` are reachable
   for legacy interop and negative tests. Each unsafe direction requires an
   explicit ``unsafe_*`` argument and emits a warning. Do not use them in
   production SAML flows.


Checklist for a production SP
-----------------------------

#. Process responses with :func:`~pygamlastan.profiles.process_response_verified`
   and a :class:`~pygamlastan.crypto.SamlVerifier` built from the **trusted**
   IdP certificate (from signature-verified MDQ or a vetted local file).
#. Use :class:`~pygamlastan.security.SecurityConfig` defaults (or ``strict()``);
   never ``permissive()``.
#. Pass a shared, fail-closed replay cache; pass a persistent-ID store whenever
   persistent NameIDs are in use.
#. Do not pass ``now``; do not set any ``unsafe_*`` flag.
#. Let the binding parse — never hand SAML XML to a third-party parser that does
   not reject DTDs and bound entity expansion.

Checklist for a production IdP
------------------------------

#. Sign assertions/responses with your real key (file or PKCS#11/HSM — see
   :doc:`signing`).
#. Pass the true ``authn_instant`` (e.g. ``user.last_login``) whenever a browser
   session may be reused, so freshness is reported honestly.
#. Verify inbound ``AuthnRequest`` signatures if your threat model requires them.
#. Apply attribute-release and NameID policy appropriate to your privacy
   requirements (see :doc:`idp_integration`).
#. Fetch SP metadata over **signature-verified** MDQ or from a vetted local file.
#. Build ``AuthnMethodRef.inline`` from what your login flow did, never from the
   request; keep the EPTID cache private to one IdP and secret and never evicting;
   read store lookups from the primary; and run the three conformance suites
   against the real backends (see `Decisions and limits of the IdP engine and its
   backends`_).
#. When showing an SP's ``mdui:UIInfo`` on a consent screen, HTML-escape its
   display names/descriptions and allowlist logo/URL schemes to ``https:`` - the
   values are attacker-controlled (see `Untrusted metadata: display fields and
   URLs`_).
