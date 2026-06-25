Writing a new SAML profile
==========================

A SAML *profile* (Web Browser SSO, Single Logout, ECP, an eIDAS/Sweden-Connect
national profile, or your own house profile) is rarely a brand-new protocol.
It is almost always a specific **recipe** over a small set of primitives:

* shape one or more messages (``AuthnRequest``, ``Response``, ``LogoutRequest`` …),
* move them over a binding (Redirect / POST / Artifact),
* sign and/or encrypt them,
* on receipt: parse, verify the signature, run the validation suite, and
  enforce any extra rules the profile mandates,
* map attributes between the wire and your application.

pygamlastan exposes each of those steps as a primitive, so most profiles are
written in **pure Python** by composing them. This guide shows how, and is
honest about the three cases you may hit - from "trivial" to "needs a small
Rust binding addition". The design rationale is recorded in the project's
Architecture Decision Records (``adr/0001-profile-extension-surface.md``).

.. contents::
   :local:
   :depth: 1


The three tiers
---------------

.. list-table::
   :header-rows: 1
   :widths: 12 40 18

   * - Tier
     - Your profile is…
     - Effort
   * - 1
     - a recomposition of existing primitives (different message shaping,
       attribute policy, NameID strategy, orchestration)
     - Easy, pure Python
   * - 2
     - tier 1 **plus** custom security policy or extra per-response checks
     - Moderate, pure Python
   * - 3
     - built on machinery gamlastan implements but pygamlastan does not yet
       bind (SLO flow, ECP/PAOS, artifact resolution, NameID management, …)
     - Add a thin Rust binding module


Tier 1 - compose the primitives
-------------------------------

Everything you need to drive a request/response profile is already bound. The
example below is a complete, minimal SP-side Web-SSO profile written entirely in
Python: build the request, send it signed over HTTP-Redirect, then verify and
validate the response.

.. code-block:: python

   from pygamlastan import core, crypto, bindings, profiles, security, xml

   IDP = "https://idp.example.org"
   SP = "https://sp.example.org/sp"
   ACS = "https://sp.example.org/acs"

   # --- Outbound: build and sign an AuthnRequest, encode it for redirect ---
   def begin_login(signer: crypto.SamlSigner, destination: str) -> str:
       opts = profiles.AuthnRequestOptions(SP, acs_url=ACS, destination=destination)
       request = profiles.create_authn_request(opts)
       # Detached HTTP-Redirect signature over the raw query parameters.
       return bindings.redirect_encode(
           request.to_xml().encode(), is_request=True, destination=destination,
           relay_state="opaque-state", signer=signer, sig_alg="rsa-sha256",
       )

   # --- Inbound: verify the signature, then validate, in one safe call ---
   def finish_login(response_xml: str, verifier: crypto.SamlVerifier) -> dict:
       cfg = security.SecurityConfig()              # production-safe defaults
       cfg.require_signed_assertions = True
       result = profiles.process_response_verified(  # verifies internally
           response_xml, verifier, cfg, SP, ACS, IDP,
           expected_request_id="_req123",
           replay_cache=security.InMemoryReplayCache(),
       )
       return result.attributes_dict()

.. important::

   Always bind validation to **real** crypto. ``process_response_verified``
   verifies the XML-DSig over the exact bytes itself and refuses to proceed if
   the signature is missing or invalid - prefer it over hand-passing
   ``verified_signed_ids`` to :func:`pygamlastan.profiles.process_response`.
   See :doc:`validation` for the lower-level path.

The primitives a profile typically reaches for:

.. list-table::
   :header-rows: 1
   :widths: 26 74

   * - Need
     - Use
   * - Build / parse any message
     - :doc:`../api/core` constructors, :doc:`../api/xml` ``parse_*``
   * - Sign / verify / encrypt / decrypt, canonicalize, HSM
     - :doc:`../api/crypto`
   * - Redirect / POST / Artifact transport
     - :doc:`../api/bindings`
   * - Validation suite + replay cache
     - :doc:`../api/security`
   * - Metadata endpoints / certificates
     - :doc:`../api/metadata`
   * - Attribute wire ⇄ local conversion, eduPersonTargetedID
     - :doc:`../api/attribute_map`, :doc:`../api/idp`


Tier 2 - custom security policy and extra checks
------------------------------------------------

Tune the full policy
~~~~~~~~~~~~~~~~~~~~~~

Every gamlastan ``SecurityConfig`` knob is individually settable, so a profile
can express its exact policy without depending on the ``strict()`` /
``permissive()`` presets:

.. code-block:: python

   cfg = security.SecurityConfig()
   # Profile mandates encrypted, signed assertions and a tight window:
   cfg.require_signed_assertions = True
   cfg.require_encrypted_assertions = True       # e.g. a PEFIM-style profile
   cfg.max_assertion_age_seconds = 120
   cfg.clock_skew_seconds = 60
   # Bind the assertion to the client's source address:
   cfg.check_client_address = True
   # Errata toggles (all default-on; shown for completeness):
   cfg.reject_signatures_with_ds_object = True   # E91
   cfg.sanitize_relay_state = True               # E90
   cfg.require_integrity_with_cbc = True         # E93

Enforce persistent-ID uniqueness (E78)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A profile that issues or consumes *persistent* NameIDs should ensure an
identifier is never silently re-bound to a different principal. Enable the
check and pass a store implementing
``check_and_record(name_id, sp_entity_id, principal) -> bool`` (return ``False``
to signal a conflict). Any backend works - here a dict, in production a
database row with a unique constraint:

.. code-block:: python

   class DbPersistentIdStore:
       def __init__(self, conn):
           self.conn = conn

       def check_and_record(self, name_id, sp_entity_id, principal):
           row = self.conn.fetchone(
               "SELECT principal FROM persistent_ids WHERE nid=? AND sp=?",
               (name_id, sp_entity_id),
           )
           if row is None:
               self.conn.execute(
                   "INSERT INTO persistent_ids(nid, sp, principal) VALUES (?,?,?)",
                   (name_id, sp_entity_id, principal),
               )
               return True
           return row[0] == principal   # False => reassignment, rejected

   cfg = security.SecurityConfig()
   cfg.enforce_persistent_id_uniqueness = True   # default True; explicit here
   result = security.validate_response(
       response, cfg,
       received_url=ACS, expected_idp_entity_id=IDP,
       sp_entity_id=SP, acs_url=ACS, expected_request_id="_req1",
       persistent_id_store=DbPersistentIdStore(conn),
   )

.. note::

   The store fails **closed**: if your ``check_and_record`` raises, the adapter
   treats it as a conflict and the uniqueness check fails.

Layer profile-specific checks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

gamlastan runs its 32-check suite as a unit. To add a 33rd, profile-specific
rule, run the suite and then apply your own check on the parsed response - you
do **not** have to re-walk the document, because every built-in outcome is
addressable and you already hold the typed objects:

.. code-block:: python

   result = security.validate_response(
       response, cfg, received_url=ACS, expected_idp_entity_id=IDP,
       sp_entity_id=SP, acs_url=ACS, expected_request_id="_req1",
   )

   # Pull one built-in outcome out of the run by number or name:
   age_check = result.get(0)                       # checklist #0
   audience = result.by_name("Audience restriction")

   # A profile rule: require a specific Authentication Context class.
   REQUIRED_ACR = core.AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT
   def profile_ok(response) -> bool:
       for assertion in response.assertions:
           for st in assertion.authn_statements:
               if st.authn_context.authn_context_class_ref != REQUIRED_ACR:
                   return False
       return True

   accepted = result.is_valid() and profile_ok(response)

For freshness-only gating you can also run the one check gamlastan exposes
standalone, without a full validation pass:

.. code-block:: python

   check = security.check_assertion_age(cfg, assertion.issue_instant, now)
   if not check.passed:
       reject(check.detail)


Tier 3 - profiles that need unbound machinery
---------------------------------------------

gamlastan already implements Single Logout, ECP/PAOS, Artifact Resolution,
Assertion Query, NameID Mapping/Management, PEFIM and the Sweden-Connect
profile - but pygamlastan does not bind all of them yet. If your profile builds
on one of these, the hard cryptographic and protocol work is **already done in
Rust**; what remains is to surface it.

Adding a binding module follows the established pattern (see any file under
``src/``): wrap the gamlastan type in a ``#[pyclass]``, expose its methods as
``#[pymethods]``, convert errors with the helpers in ``src/errors.rs``, and
register the submodule in ``src/lib.rs``. Each existing module is ~150-450 lines
of mechanical wrapping with no new security logic. The Logout message *types*
are already bound (:func:`pygamlastan.xml.parse_logout_request` and friends), so
a Single-Logout profile is mostly a matter of binding the SLO flow helpers.

If a profile needs genuinely new SAML *semantics* that gamlastan does not
implement, that belongs upstream in gamlastan rather than in the binding.


A checklist for a new profile
-----------------------------

#. **Messages** - can you build/parse them with :doc:`../api/core` /
   :doc:`../api/xml`? (Logout, AuthnRequest, Response, Assertion: yes.)
#. **Transport** - Redirect / POST / Artifact via :doc:`../api/bindings`?
#. **Crypto** - signing/verification/encryption rules expressible with
   :doc:`../api/crypto` (algorithms, HSM, c14n)?
#. **Policy** - all rules covered by ``SecurityConfig`` fields, or a small
   Python check layered on the result?
#. **Identity** - NameID strategy, persistent-ID uniqueness, attribute mapping?
#. **Gap?** - if a step needs an unbound gamlastan profile (tier 3), add a
   binding module following the existing pattern.

Tiers 1-2 cover the large majority of real-world profiles and stay in Python.
