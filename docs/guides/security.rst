Security guide
==============

SAML is a security protocol whose entire value depends on getting a handful of
checks exactly right. ``pygamlastan`` is a thin binding: the cryptography and
the 32-check validation suite live upstream in ``gamlastan`` / ``bergshamra`` /
``kryptering``. This guide describes the security properties the **binding**
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

   verified = verifier.verify_enveloped(response_xml)   # real XML-DSig check
   parsed = xml.parse_response(response_xml)            # same bytes
   result = profiles.process_response(
       parsed, security.SecurityConfig(), sp_entity_id, acs_url, idp_entity_id,
       verified_signed_ids=verified.signed_reference_ids(),   # from the verifier, not hand-built
       replay_cache=security.InMemoryReplayCache(),
   )

When in doubt, use ``process_response_verified`` and let the binding do the
binding.


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

* **Fail-closed resource limits** (uppsala 0.5): element nesting depth (128),
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

* **Persistent-ID store.** When a response carries a persistent NameID, a
  persistent-ID store is required so NameID **reassignment** (one identifier
  re-pointed at a different subject) is detected. This adapter also fails closed:
  a Python-side error is treated as a conflict.

* The ``unsafe_no_replay_cache`` / ``unsafe_no_persistent_id_store`` flags exist
  only to make the requirement explicit and opt-out-able in tests. The ``unsafe_``
  prefix is a deliberate signpost: do not set them in production.


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
#. When showing an SP's ``mdui:UIInfo`` on a consent screen, HTML-escape its
   display names/descriptions and allowlist logo/URL schemes to ``https:`` - the
   values are attacker-controlled (see `Untrusted metadata: display fields and
   URLs`_).
