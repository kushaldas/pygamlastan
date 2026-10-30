# Changelog

All notable changes to `pygamlastan` are documented in this file.

The project is pre-1.0, so minor releases may include behavior changes where
needed to track the upstream `gamlastan` SAML library and correct protocol or
security handling. `pygamlastan` is a thin PyO3 binding; most entries below
reflect adopting a change made in `gamlastan` / `uppsala` / `bergshamra` and
surfacing it correctly to Python.

## [Unreleased]

Tracks gamlastan `main` (the IdP orchestrator from PR #43 and the 0.10.0
dependency stack), which is not yet released; `Cargo.toml` carries a git
`[patch.crates-io]` until 0.10.0 is on crates.io.

### Changed

- Bumped `gamlastan` to 0.10.0 (bergshamra 0.11, uppsala 0.12) and `kryptering`
  to 0.7.0, which gamlastan 0.10.0 requires. The kryptering feature list gains
  `rustcrypto`, mirroring gamlastan. No source changes were needed for the
  kryptering 0.7 API.
- **Breaking:** the Python `IdentityStore` protocol passed as
  `IdentDb(store=...)` is now record-shaped (one record per user/NameID):
  `for_user`, `user_for`, `get_or_insert_durable`, `insert`, `replace`,
  `remove`, `remove_all`, and an optional `find_durable`. The old
  `get`/`set`/`remove` key-value protocol no longer applies to `IdentDb`. The
  backend must enforce the two unique constraints documented on the protocol.
- **Breaking:** store-backed calls now raise instead of falling back to "not
  found". `IdentDb` methods, `Eptid` methods and `InMemoryAssertionStore`
  methods raise `SamlStoreError` on a backend failure. A Python store reports a
  conflict by raising `NameIdValueTaken` or `NameIdDurableExists`.
- Email and unspecified NameIDs are now stable per (user, SP, format), like
  persistent ones. Transient NameIDs are no longer stored.

### Security

- `SamlStoreError` is no longer a `SamlIdentError`. Code written before store
  errors existed wraps identity calls in `except SamlIdentError` to mean "no such
  principal"; with the old hierarchy that handler would have turned a database
  outage back into a missing record.
- A record a Python `IdentityStore` returns from `find_durable` or
  `get_or_insert_durable` is now checked before it is used: it must be the
  durable slot that was asked for, and `user_for(value)` must name the same user,
  otherwise `SamlStoreError`. A backend with a wrong filter, index or cache could
  otherwise hand one user another user's persistent NameID. This adds one
  `user_for` call per lookup, and requires `user_for` to see the backend's own
  writes (not a lagging replica).

### Added

- The IdP response engine, `pygamlastan.idp.ResponseEngine`, with
  `check_request`, `create_authn_response` and `create_denial_response`, and the
  types they use: `ResponseParams`, `AuthenticatedSubject`, `AuthnMethodRef`
  (`inline` / `broker`), `EstablishedSession`, `Disposition`, `Denial`,
  `ResponseOutcome`, `IssuedResponse` and `DeniedResponse`. `release="policy"`
  filters through the `ReleasePolicy`; `release="pass_through"` is for a proxy
  whose attributes were filtered upstream. A store failure is `SamlStoreError`
  and any other fault `SamlProfileError`; neither is ever a signed denial.
- `IdentDb.find_nameid(user_id, format=None, sp_name_qualifier=None,
  name_qualifier=None, sp_provided_id=None)` (pysaml2 `find_nameid`), and an
  optional `find(...)` on the Python store protocol to push the filter into a
  query. The records a pushed-down `find` returns are checked like the durable
  lookups: each must satisfy the filter and belong to the user, otherwise
  `SamlStoreError`. The conformance suite now exercises the backend's own `find`.
- `idp.check_store_conformance(new_store, threads=16)`, `check_store_conformance_one`
  and `STORE_CONFORMANCE_CHECKS`: gamlastan's `IdentityStore` conformance suite,
  runnable from Python against a real backend (a missing unique index compiles
  fine and only misbehaves under load). It releases the GIL while it runs, since
  the concurrent checks call the store from several threads. A failure raises
  the new `StoreConformanceError` with `.check` and `.message`.
- `PolicyEntry` settings `session_lifetime_seconds`, `supported_nameid_formats`,
  `signing_preference` and `deny_unconfigured_release`, with the matching
  `ReleasePolicy` readers, and the module constants `ISSUABLE_NAMEID_FORMATS` and
  `MAX_NAMEID_FORMAT_LEN`. `supported_nameid_formats` and
  `deny_unconfigured_release` are opt-ins: by default any requested NameID
  format is accepted and every attribute the application supplies is released
  to an SP no rule covers, as in pysaml2.
- `pygamlastan.crypto.SignatureMethod`, `DigestMethod`, `SigningPreference` and
  `SigningAlgorithms`: per-SP signature and digest algorithm selection (SHA-2
  RSA and ECDSA only; the SP's metadata can only choose among your entries).
- `AuthnBroker(allow_exact_level_matching=...)` and `AuthnBroker.is_empty()`.
- `IdentDb(persist_transient=True)`, to store transient NameIDs so
  `find_local_id` can resolve one (a back-channel logout needs it). Without it,
  which is the default, they are not stored.
- `AuthnRequest.requested_subject_name_id()` and `has_requested_subject()`, and
  `ProcessedAuthnRequest.requested_sp_name_qualifier`, `has_name_id_policy` and
  `requested_authn_context_decl_refs`.
- `SamlStoreError`, `NameIdValueTaken` and `NameIdDurableExists` exceptions.
  `NameIdValueTaken` and `NameIdDurableExists` are `SamlIdentError`s;
  `SamlStoreError` is a direct child of `SamlError` on purpose, so an existing
  `except SamlIdentError` (which meant "no such principal") cannot swallow a
  database outage.
- `ResponseOptions(authenticating_authorities=...)`.
- `Eptid(secret, digest="pysaml2-md5", allow_legacy_md5=True)` reproduces stock
  pysaml2 MD5 EPTID values for migrations; the default stays SHA-256 and is not
  byte-compatible with pysaml2.
- `Eptid(store=...)`: a Python object with `get(key)`, `set(key, value)` and
  `remove(key)` to persist the cache of issued values, so a later change of
  secret or digest cannot change what an SP already knows. A failing store is
  `SamlStoreError`, never a recompute. Keys are `eptid:<idp>__<sp>__<user>`;
  pysaml2 keys its cache `<sp>__<user>`, so an adapter over an existing pysaml2
  collection must translate them.

## [0.6.0] - 2026-09-14

### Added

- Exposed the compat shim's signature/digest algorithm policy as SP settings:
  `service.sp.allowed_signature_algorithms` and `service.sp.allowed_digest_algorithms`
  (both `list[str]`, default unset). `SamlVerifier` already supported a
  configurable `AlgorithmPolicy`, but `compat.saml2` had no config surface
  reaching it, so a deployment could not opt into a non-default algorithm
  without patching `pygamlastan` itself. Mirrors `allow_unsigned_logout_requests`'s
  existing shape as an explicit opt-in; the default policy is unchanged unless
  these are set. The configured algorithms are added on top of the verifier's
  secure defaults, never replacing them. **This is an SP-wide setting**: it
  applies to every IdP the SP verifies against (AuthnResponse, LogoutResponse,
  and LogoutRequest alike), not only the specific IdP that needs the legacy
  algorithm - there is no per-IdP scoping, matching `signing_algorithm`/
  `digest_algorithm`'s existing SP-wide shape.

### Fixed

- `compat.saml2.config.SPConfig.load()` no longer requires every IdP entity in
  a loaded metadata document to carry a signing certificate. pysaml2 never
  validated this eagerly either — `mdstore.certs()` resolves a signing
  certificate lazily, per entity, only when that specific entity is actually
  used for verification. The compat shim's eager, whole-document check meant
  any SP pointed at a real third-party federation aggregate (e.g. an MDX
  `role/idp.xml` bulk document) could fail to load entirely because of an
  unrelated entity it never talks to. `idp_signing_certs()` already enforces
  the requirement correctly at the point it matters; only the redundant,
  over-eager duplicate at load time is removed.

## [0.5.0] - 2026-09-04

Adopts the upstream `gamlastan` 0.9 security release and its matching
`bergshamra` 0.9 / `uppsala` 0.10.1 XML stack.

### Added

- Exposed `crypto.AlgorithmPolicy`, including secure defaults, exact allowlists,
  permissive legacy mode, allowlist inspection, and verifier setter/builder
  integration. `SamlVerifier` also exposes the independent HMAC guard.
- Added `logout.validate_logout_request_with_replay`, which enforces bounded
  freshness and issuer-scoped one-time use through built-in or Python replay
  caches.
- Added `profiles.SessionParticipant`, `profiles.SamlSession`, and the complete
  built-in session-store surface, including participant-aware lookup and atomic
  removal. `SessionParticipant.sp_provided_id` and IdP logout propagation are
  available end to end.
- Documented gamlastan 0.9's recipient-aware artifact-store protocol methods.
- Exposed `SecurityConfig.allow_unsolicited_responses` and the pysaml2-compatible
  `service.sp.allow_unsolicited` setting.

### Changed

- Refreshed the compatible PyO3 patch release from 0.29.0 to 0.29.2.
- Refreshed compatible Rust dependency patches, including `chacha20` 0.10.2;
  this removes the yanked 0.10.1 release previously selected through
  `gamlastan`'s `rand` dependency.

### Security

- Unsolicited SSO is rejected by default in both the compatibility shim and the
  native Python-backed-store response-processing path; deployments must opt in.
- SHA-1 remains rejected by default. An exact `AlgorithmPolicy` can opt into a
  named legacy method, while the older `unsafe_allow_weak_sha1` path now widens
  only for that method instead of making the entire verifier permissive.
- The pysaml2 SLO compatibility path rejects future, stale, replayed, and
  destination-mismatched requests, including requests whose far-future
  `NotOnOrAfter` attempts to revive an old `IssueInstant`.
- The built-in replay cache adopts gamlastan 0.9's insertion-time pruning and
  no longer retains entries whose supplied expiry is already due.

## [0.4.0] - 2026-09-02

Adopts the upstream `gamlastan` 0.8 hardening release. This is an API-breaking
release for the IdP request-processing, Single Logout, and persistent-NameID
surfaces; see the migration notes inline.

### Changed

- **Upgraded the upstream library baseline to the released `gamlastan` 0.8.0.**
  The Rust dependency now tracks `kryptering` 0.5 and pulls the matching `uppsala` 0.9 /
  `bergshamra` 0.8 XML-security stack, all consumed from crates.io.
- **`profiles.process_authn_request(request, sp_metadata, request_signature_verified=False)`**
  — `sp_metadata` is now a required positional argument (the
  `unsafe_allow_missing_metadata` escape hatch is gone) and a new
  `request_signature_verified` argument carries transport-verified signature
  provenance. gamlastan resolves the ACS location together with its registered
  binding, and enforces the SP's `AuthnRequestsSigned` policy. The binding also
  requires the request `Issuer` to be present and equal to the supplied
  metadata's `entityID` - otherwise metadata for one SP processed alongside a
  request claiming another would return the claimed entity id while enforcing
  the wrong SP's endpoints and signing policy. `ProcessedAuthnRequest` gains an
  `authn_context_comparison` getter.
- **`logout.validate_logout_request(request, expected_issuer, signature_verified, now, clock_skew_seconds=180)`**
  — now takes the trusted `expected_issuer` and a `signature_verified` proof;
  the Issuer must match and an unverified request is rejected.
- **`SpLogoutOrchestrator.handle_response(response, signature_verified)`** — now
  requires a `signature_verified` proof; correlation alone can no longer
  authenticate a LogoutResponse.
- **`profiles.process_response` / `process_response_verified` / `security.validate_response`**
  gain a `persistent_id_principal` argument. Enabling persistent-NameID
  uniqueness (E78) now requires both a `persistent_id_store` and this independent
  local principal; `LogoutRequest` gains `has_signature` and `not_on_or_after`
  getters.
- Metadata parsing (`metadata.parse_entity` / `parse_entities`) now uses
  gamlastan's `parse_secure_metadata`, which keeps every hardening guard while
  accepting the structural comments and processing instructions real federation
  aggregates carry (a comment/PI that splits a signed text value is still
  rejected).
- Refreshed the Python dependencies of the `examples/django-idp` and
  `examples/django-sp` apps (Django 6.0.7, cryptography >=50, gunicorn >=26,
  whitenoise >=6.12) and the dev tooling (pytest >=9).

### Security

- **Replay protection is now effectively mandatory.** gamlastan fails the
  replay check (20) closed when no replay cache is configured, so
  `unsafe_no_replay_cache=True` can no longer produce a valid result — it only
  relocates the failure from the binding precondition into the validation
  output. Supply an `InMemoryReplayCache` or a protocol implementation. The
  pysaml2 compat SP shim now holds a replay cache shared across every
  `Saml2Client` instance for the lifetime of the process (rebuilding the client
  per request no longer resets replay state); multi-process deployments can
  inject a shared implementation via `Saml2Client(config, replay_cache=...)`.
  The shim also evicts expired entries by scheduling a throttled
  `cleanup()` from its processing paths - gamlastan's `check_and_insert`
  never removes other entries on its own, so a long-running SP would
  otherwise grow the cache without bound. The throttle is tracked per cache,
  so several injected caches each receive periodic maintenance instead of one
  cache's traffic starving the others. Replay keys in the compat shim are now
  stable ASCII values namespaced by message kind, local SP entity ID, and
  trusted expected IdP. This prevents an assertion or LogoutRequest in one
  trust context from reserving the same raw SAML ID in another context and
  causing a cross-context denial of service. Existing raw keys in persistent
  injected caches are not reused after this key-schema change; deployments
  requiring uninterrupted replay memory should drain the previous messages'
  validity window before switching versions.
- **Persistent-NameID uniqueness (E78) is now opt-in and correctly keyed.** It
  defaults off and, when enabled, is keyed by an application-supplied
  `persistent_id_principal` established independently of the asserted NameID
  (the previous behavior keyed it by the NameID itself and could never detect a
  reassignment). Supplying a `persistent_id_store` without a principal only
  errors when the check actually applies (E78 enabled and the response carries
  a persistent NameID); a dormant store is ignored, so callers that always
  inject one keep working with the opt-in default.
- **Partial Redirect signature tuples are rejected, never downgraded to
  "unsigned".** The decoder permits `SigAlg` without `Signature`, so stripping
  one parameter must not turn a signed request into an unsigned one: the
  django-idp example, the IdP integration guide, and the compat SP's
  `handle_logout_request` now fail on an incomplete
  SigAlg/Signature/signed-query tuple before any verification decision - in
  the compat SP the check runs before the certificate lookup, so the
  no-certificate development fallback cannot accept a partial tuple either.
- **The pysaml2 compat SP now cryptographically verifies inbound LogoutRequests**
  (`Saml2Client.handle_logout_request`) against the IdP's metadata signing
  certificates before destroying any session. When no signing certificate is
  configured for the IdP it **fails closed** unless the SP settings explicitly
  opt in with `allow_unsigned_logout_requests: True` (development /
  transport-authenticated parity; the opt-in still warns on every accepted
  unsigned request) - a silent production metadata omission cannot downgrade
  the endpoint to unsigned requests. Configure IdP metadata with a signing
  certificate to enforce signatures. The Redirect binding accepts the detached
  signature via `sig_alg` / `signature` / `signed_query` keyword arguments, and
  the signed query is bound to the processed message before its signature
  counts: the `SAMLRequest` it carries must decode to the exact LogoutRequest
  XML under validation and its `SigAlg` must be the algorithm used for
  verification, so a valid signed query captured from another request cannot
  vouch for a substituted one. Verified LogoutRequests are also **one-time
  use**: the request ID is recorded atomically in the shared replay cache
  before the success response authorizes session destruction. A request that
  declares `NotOnOrAfter` is retained through that window (plus skew); one
  without `NotOnOrAfter` is subject to the shim's own 24h age limit from
  `IssueInstant`, with the replay entry retained past that whole window - so a
  captured request can never outlive its replay entry and be accepted again.
  An `IssueInstant` more than the 180s clock skew in the future is rejected
  outright, and a request-declared `NotOnOrAfter` further ahead than the same
  24h window is rejected too, so a forged timestamp or validity window cannot
  pin replay entries arbitrarily far into the future.
  The signed Redirect query's `RelayState` must also equal the one the handler
  echoes back (or be absent from both), so an unsigned `RelayState` cannot
  ride along a valid signature. A present `Destination` must name one of this
  SP's configured SLO endpoints for the received binding, so a request validly
  signed by the trusted IdP but addressed to a different SP or binding cannot
  be relayed here to destroy a session. Deployments accepting multiple
  bindings at one URL must configure that URL for each binding. The
  no-certificate development fallback
  applies only to an IdP actually present in the SP configuration or
  metadata - an arbitrary caller-supplied `expected_idp` is rejected instead
  of becoming a trusted unsigned issuer.
- **Binding output is decoded strictly before verification** in the example
  apps and guides: the exact `saml_xml` bytes are decoded as strict UTF-8
  instead of the lossy, display-only `saml_text` projection, so malformed
  input is rejected rather than silently transformed into different XML than
  the bytes the binding authenticated.
- **Signature verification is key-rollover aware.** The compat SP (Response and
  LogoutRequest verification, via the new `SPConfig.idp_signing_certs`) and the
  django-idp example (AuthnRequest verification) now try every signing
  certificate published in metadata instead of only the first, so a signature
  produced with either the old or the new key during a rollover still verifies.
  The Redirect loops tolerate a certificate that makes verification *raise*
  (e.g. a key-type/algorithm mismatch on a retired key) and keep trying the
  remaining certificates, failing only after all were attempted. The enveloped
  loops check `VerifyResult.is_valid()` explicitly - `verify_all_enveloped`
  can *return* an invalid result (e.g. a tampered `SignatureValue`) rather
  than raising, and reference IDs only count when every signature present
  verifies.

## [0.3.0] - 2026-07-07

### Added

- **Single Logout (SLO) binding (`pygamlastan.logout`).** Surfaces
  `gamlastan::profiles::logout`: the SP-initiated `SpLogoutRequestOptions` +
  `create_sp_logout_request` builder; the transport-agnostic
  `SpLogoutOrchestrator` state machine (the equivalent of pysaml2's
  `global_logout`/`handle_logout_response` loop, with an anti-spoofing
  issuer-match check on each correlated response); the `LogoutResponse` builders
  `create_logout_response_success` / `_partial` / `_error`; and
  `validate_logout_request`. IdP-propagated logout
  (`create_idp_propagation_request`) is deferred pending a `profiles::session`
  binding. See ADR 0004.
- **IdP identity database (`idp.IdentDb`).** Binds `gamlastan::idp::ident`: the
  pysaml2 `IdentDB` equivalent - transient/persistent NameID generation,
  `construct_nameid` honoring an incoming `NameIDPolicy`, the
  user<->NameID mapping (`store`/`find_local_id`/`match_local_id`/
  `name_ids_for`), the server side of ManageNameID (`manage_name_id_new_id` /
  `manage_name_id_terminate`) and NameIDMapping
  (`handle_name_id_mapping_request`), and removal. Backed by the built-in
  in-memory store or any Python object implementing the `get`/`set`/`remove`
  `IdentityStore` protocol (so deployments can persist to Redis/SQL/Mongo). The
  AssertionIDRequest / AuthnQuery response builders are deferred (they need the
  query-message parsing surface and are unused by the SSO/SLO flow).
- **IdP attribute-release policy + entity categories (`idp.ReleasePolicy`,
  `idp.PolicyEntry`, `idp.EntityCategoryRule` / `EntityCategoryPolicy`,
  `idp.SignTargets`).** Binds `gamlastan::idp::policy` and
  `idp::entity_category`: per-SP / per-registration-authority / default release
  with `register_sp_metadata` reading `mdrpi:RegistrationInfo`, entity-category
  release (shipped SWAMID/REFEDS/InCommon/eduGAIN/REFEDS-Access/at_egov_pvp2
  policies by name plus developer-defined custom categories), required/optional
  filtering, regex value restrictions, the subject-id/pairwise-id mutual
  exclusion (`subject_id_req="any"`), assertion lifetime, NameID format /
  NameFormat, and signing targets. Plus the standalone `releasable_attributes`
  engine, `subject_id_req_from_metadata`, and the entity-category / subject-id
  URI constants. See ADR 0005. The lower-level `filter_*` helpers and the
  metadata-driven `restrict` overload are not bound (the single `filter`
  pipeline covers the flow).
- **Metadata extension accessors (`metadata.EntityDescriptor`).**
  `registration_authority`, `entity_categories()`, `entity_attribute_values()`,
  `entity_attributes()`, `supported_algorithms()`, `ui_info(role)` (returning
  `metadata.UiInfo` / `UiLogo`), and `requested_attributes(acs_index)`
  (the SP's `(required, optional)` requested attributes as `core.Attribute`
  lists, ready for `idp.ReleasePolicy.filter`). Parsing `mdui:UIInfo` and
  `alg:SigningMethod` / `alg:DigestMethod` required upstream gamlastan work
  (extending `MdExtensions`, plus a namespace-resolution fix so role-level
  Extensions whose prefixes are declared on the EntityDescriptor root parse
  correctly). See ADR 0006.
- **`profiles.create_error_response`.** Build an assertion-less error Response
  carrying a status-code URI (e.g. `core.STATUS_RESPONDER`) and optional message,
  delivered to the SP's ACS (pysaml2 `create_error_response`).
- **pysaml2 SP compatibility shim (`pygamlastan.compat.saml2`).** A pure-Python,
  drop-in subset of the pysaml2 SP-side API backed by this binding, so a pysaml2
  Service Provider can migrate by swapping `from saml2 import X` for
  `from pygamlastan.compat.saml2 import X` while leaving its web-framework and
  session code untouched: `Saml2Client` (AuthnRequest preparation, response
  parsing, Single Logout), `SPConfig`, the pysaml2-shaped `AuthnResponse` /
  `session_info`, NameID `code`/`decode`, `Cache`, and templated SP metadata.
  Untrusted XML is parsed through `parse_secure` and signed responses are
  validated with `profiles.process_response_verified` (no xmlsec1 subprocess).
  See `docs/adr/0007-pysaml2-compat-shim.md` and the pysaml2 compatibility guide.

### Changed

- **Upgraded the upstream library baseline to the released `gamlastan` 0.7.0.**
  The Rust dependency now tracks `kryptering` 0.4.1 and pulls the matching `uppsala` 0.9 /
  `bergshamra` 0.7 XML-security stack.

## [0.2.0] - 2026-06-27

### Security

- **Hardened XML parsing for all untrusted input.** Every parse entry point that
  handles attacker-controlled XML now goes through
  `gamlastan::xml::parse_secure` instead of the raw `uppsala::parse`. This
  applies to `xml.parse_response`, `xml.parse_authn_request`,
  `xml.parse_assertion`, `xml.parse_logout_request`, `xml.parse_logout_response`,
  `metadata.parse_entity`, `metadata.parse_entities`, and the parse performed
  inside `profiles.process_response_verified`. `parse_secure` adds two defenses
  on top of the parse:
  - **DTD / `<!DOCTYPE>` rejection** — any document carrying a DTD is refused
    with a `SamlXmlError`. Legitimate SAML messages never contain a DTD, so this
    removes the XXE / external-entity / entity-smuggling entry point from all
    downstream SAML handling.
  - **Fail-closed resource limits** (inherited from uppsala 0.5) — element
    nesting depth (128), entity-expansion byte budget (1 MiB), and entity nesting
    depth (256). These bound billion-laughs / quadratic-blowup amplification and
    deep-nesting stack exhaustion *before* assertion validation runs.

  These protections are applied inside the binding and cannot be bypassed from
  Python — there is no API that exposes the raw, unhardened parser. See
  [ADR 0002](docs/adr/0002-parse-secure-untrusted-xml.md).

- Adopted the upstream `gamlastan` 0.5 → 0.6 security fixes by upgrading the
  dependency. Among them: ACS signature verification before claim extraction,
  fail-closed Web SSO bearer-control validation, SOAP/ECP envelope wrapping
  defenses, namespace-aware `ds:Object` (errata E91) rejection, redirect/POST
  binding parameter-pollution rejection, and rejection of opaque encrypted-only
  generic-SP responses. See the upstream
  [gamlastan CHANGELOG](https://github.com/kushaldas/gamlastan/blob/main/CHANGELOG.md)
  and its ADRs 0016–0024 for the full list.

- Cleared the upstream `cargo audit` findings pulled in transitively
  (`quinn-proto` RUSTSEC-2026-0185, `rand` RUSTSEC-2026-0097, the yanked
  `crypto-bigint` 0.7.3) and dropped the unmaintained `rustls-pemfile`
  (RUSTSEC-2025-0134) from the example IdP stack.

### Changed

- **Upgraded the XML/crypto stack.** `gamlastan` 0.5.0 → 0.6.0 (consumed from the
  local `../saml/crates/gamlastan` path), `kryptering` 0.3 → 0.4.0, which in turn
  pulls `uppsala` 0.5 and `bergshamra` 0.6. The direct `kryptering` dependency
  now mirrors gamlastan's feature set (`legacy`, `post-quantum`, `pkcs11`) so the
  shared `Signer` / `Pkcs11Signer` types resolve to a single instance with no
  version or feature drift across the FFI boundary.

- **`profiles.create_response` and `profiles.create_unsolicited_response` now
  accept a separate `authn_instant`.** Upstream split the single `now` into
  `ResponseTimes { issue_instant, authn_instant }` (gamlastan ADR 0025). The
  Python API keeps `now` as the document issue instant and adds an optional
  `authn_instant`:
  - `now` (default: current wall clock) drives `IssueInstant`,
    `Conditions/@NotBefore`, and every `NotOnOrAfter`.
  - `authn_instant` (default: `now`) drives `AuthnStatement/@AuthnInstant` — the
    time the principal actually authenticated.

  This is a **backward-compatible** addition: existing calls that omit
  `authn_instant` behave exactly as before (a fresh login, both instants equal).
  See [ADR 0003](docs/adr/0003-authn-instant-response-times.md).

- Bumped the build toolchain pin from `maturin==1.9.6` to `maturin==1.14.1`
  (`pyproject.toml` and `build-wheels.sh`).

### Fixed

- IdP responses no longer over-report authentication freshness when an existing
  SSO session is reused. When a previously authenticated principal's session is
  reused, the real authentication time may predate response generation; passing
  `authn_instant` keeps `AuthnStatement/@AuthnInstant` truthful for SPs that
  enforce it (`ForceAuthn` / `RequestedAuthnContext` / max-age). The
  `examples/django-idp` `_issue()` view now passes `user.last_login` to
  demonstrate the correct pattern.

### Examples

- `examples/django-idp`: `build_signed_response` accepts and forwards
  `authn_instant`; the `_issue` view supplies `request.user.last_login` for
  reused sessions. README documents the freshness semantics and the automatic
  `parse_secure` hardening.
- `examples/django-sp`: README security notes now cover the `parse_secure`
  DTD/XXE and resource-limit hardening and reiterate that
  `process_response_verified` is the only safe response entry point.

### Tests

- Added coverage for DTD/`<!DOCTYPE>` rejection (XXE payload), billion-laughs
  rejection, and the `authn_instant` / `issue_instant` separation.

## [0.1.1] - earlier

Initial released binding over `gamlastan` 0.5.0. See the Git history for the
change set prior to this changelog.

[0.4.0]: https://github.com/kushaldas/pygamlastan/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kushaldas/pygamlastan/compare/ee774370e76d5dd422ddfbe59ed264ed4367918a...v0.3.0
[0.2.0]: https://github.com/kushaldas/pygamlastan/compare/v0.1.1...ee774370e76d5dd422ddfbe59ed264ed4367918a
