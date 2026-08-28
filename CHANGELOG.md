# Changelog

All notable changes to `pygamlastan` are documented in this file.

The project is pre-1.0, so minor releases may include behavior changes where
needed to track the upstream `gamlastan` SAML library and correct protocol or
security handling. `pygamlastan` is a thin PyO3 binding; most entries below
reflect adopting a change made in `gamlastan` / `uppsala` / `bergshamra` and
surfacing it correctly to Python.

## [0.4.0] - 2026-08-28

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
  whitenoise >=6.12) and the dev tooling (pytest >=9). The bundled example
  wheels were rebuilt for `pygamlastan` 0.4.0.

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
  otherwise grow the cache without bound.
- **Persistent-NameID uniqueness (E78) is now opt-in and correctly keyed.** It
  defaults off and, when enabled, is keyed by an application-supplied
  `persistent_id_principal` established independently of the asserted NameID
  (the previous behavior keyed it by the NameID itself and could never detect a
  reassignment).
- **The pysaml2 compat SP now cryptographically verifies inbound LogoutRequests**
  (`Saml2Client.handle_logout_request`) against the IdP's metadata signing
  certificates before destroying any session. When no signing certificate is
  configured for the IdP it warns and accepts unsigned requests (dev /
  transport-authenticated parity); configure IdP metadata with a signing
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
  The signed Redirect query's `RelayState` must also equal the one the handler
  echoes back (or be absent from both), so an unsigned `RelayState` cannot
  ride along a valid signature. The no-certificate development fallback
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
