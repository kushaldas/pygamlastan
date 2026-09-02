# ADR 0007: pysaml2 compatibility shim (`pygamlastan.compat.saml2`)

- **Status:** Accepted
- **Date:** 2026-06-28
- **Deciders:** pygamlastan maintainers

## Context

The motivating consumer of pygamlastan is eduID, today built on the SUNET fork
of **pysaml2**. eduID's SAML code is concentrated in a few SP-side modules
(`eduid_saml2.py`, `cache.py`, `utils.py`, the `authn` views and ACS actions)
that call a small, stable slice of the pysaml2 API:

- `saml2.client.Saml2Client(config, identity_cache=, state_cache=)` with
  `prepare_for_authenticate`, `parse_authn_request_response` (returning an object
  with `.session_id()` / `.session_info()`), `global_logout`,
  `parse_logout_request_response`, `handle_logout_request`;
- `saml2.config.SPConfig().load(dict)` over the existing `saml2_settings.py`;
- `saml2.ident.code` / `decode` (NameID <-> session-storable string);
- `saml2.saml.{NameID, Subject, NAMEID_FORMAT_*, NAME_FORMAT_URI}`;
- `saml2.response` wrappers, assertion confirmation objects, and status /
  signature / lifetime exception types;
- `saml2.metadata.entity_descriptor`, `saml2.cache.Cache`,
  `saml2.s_utils.deflate_and_base64_encode`, `saml2.sigver.get_xmlsec_binary`,
  metadata-store queries, mutable `samlp.Scoping` values, and the schema
  namespace modules imported by djangosaml2.

We had two questions: **how** to migrate eduID without rewriting its Flask views
and session logic, and **where** the migration code should live.

## Decision

**Provide a thin pysaml2-API-compatible facade backed by pygamlastan, and ship
it inside the pygamlastan distribution** as `pygamlastan.compat.saml2`, mirroring
the pysaml2 module layout (`client`, `client_base`, `config`, `ident`, `response`,
`saml`, `samlp`, `cache`, `metadata`, `mdstore`, `md`, `s_utils`, `sigver`,
`validate`, `xmldsig`, `xmlenc`, `server`, `typing`).
Consumers migrate most covered flows by swapping `from saml2 import X` for
`from pygamlastan.compat.saml2 import X`. Signed HTTP-Redirect SLO additionally
requires the web adapter to preserve the exact signed query; unmodified
djangosaml2 does not forward it.

Rationale for the two choices:

- **Shim, not rewrite.** The pysaml2 surface eduID uses is small and stable, and
  the value objects it passes around (the `session_info` dict, the coded NameID
  string, the `http_info` redirect dict) are easy to reproduce. A shim keeps the
  blast radius to the import lines and lets the existing eduID test suites act as
  the acceptance gate, rather than re-deriving years of flow logic.
- **Inside pygamlastan, not in eduID.** The shim is not eduID-specific: any
  pysaml2 SP consumer can reuse it. Co-locating it with the binding means it is
  versioned and tested against the exact pygamlastan release it targets, and ships
  in the same wheel (the maturin mixed layout packages everything under
  `python/pygamlastan/`, so no packaging change is needed).

**Scope: SP flow first.** Web Browser SSO (AuthnRequest creation, response
processing) and Single Logout are implemented, including djangosaml2's custom
POST request builder, metadata discovery facade, session-backed identity/state
caches, and multi-IdP selection. The IdP `server.Server` remains a Phase 2
placeholder that raises `NotImplementedError` but imports cleanly.

**Security posture is config-driven and maps onto the safe entry points.** The
shim honours pysaml2's `want_response_signed`:

- `want_response_signed=True` (production): the shim calls
  `profiles.process_response_verified`, the safe-by-construction entry point that
  verifies the XML-DSig over the exact received bytes internally (with a verifier
  built from the IdP signing certificate read from parsed metadata) and feeds
  only the cryptographically verified reference IDs into validation - so there is
  no `verified_signed_ids` to thread or mis-wire. Because verification happens
  first, a missing/invalid signature (`SamlCryptoError`) is surfaced as
  `AssertionError` before any status logic; a *verified* Response carrying a
  non-Success status is surfaced as `StatusError` for pysaml2 parity. The
  validation config uses production defaults with `require_signed_responses =
  true` and `require_signed_assertions = false`, matching pysaml2's
  `want_response_signed` switch: a signed Response envelope is required, but
  direct Assertion signatures are not implied by that setting.
- `want_response_signed=False` (dev/test only, as eduID's test settings set it):
  responses go through `profiles.process_response` with
  `SecurityConfig.permissive()`. The unsigned path is reachable **only** when the
  settings explicitly opt out of signatures.

Solicited-response and replay protection are both enforced. The caller's
outstanding-query set is checked for `InResponseTo` (an unknown value raises
`UnsolicitedResponse`), while assertion and IdP-initiated logout IDs pass through
a process-lifetime replay cache. The cache keys include message kind, local SP,
and trusted IdP; callers may inject a shared backend for multi-process
deployments. SP-initiated logout stores the generated request ID in the supplied
state cache and accepts only a correlated LogoutResponse.

**NameID `code`/`decode` support rolling migration.** New values use a
self-describing `pgc1:`-prefixed base64url(JSON) encoding. `decode` also accepts
pysaml2's legacy comma-index representation and djangosaml2's historical bare
subject text, so sessions created before the dependency swap remain usable.
Malformed `pgc1:` data still fails with `ValueError`.

**SP metadata generation and IdP metadata navigation are adapted separately.**
`metadata.entity_descriptor(config)` renders the local SP descriptor from the
configured entityID, endpoints, signing flags, and certificate. Parsed native
IdP `EntityDescriptor` values live behind a read-only `MetadataStore` facade
with the `.metadata`, `.name()`, `.service()`, and descriptor queries used by
djangosaml2; this avoids recreating pysaml2's general XML object model.

## Consequences

- eduID (and other pysaml2 SPs) migrate by changing imports only; the
  `session_info` dict, coded-NameID strings, and redirect `http_info` keep their
  pysaml2 shapes (`ava`, `name_id`, `came_from`, `issuer`, `not_on_or_after`,
  `authn_info`, `session_index`; `headers=[("Location", url)]`).
- The `xmlsec1` subprocess and `pyXMLSecurity` dependency disappear: signing and
  verification happen in-process in Rust, and `sigver.get_xmlsec_binary` returns
  `None`. Untrusted XML is parsed through gamlastan's `parse_secure` (DTD/XXE
  rejection + resource limits), so SP response/metadata parsing is hardened by
  default (ADR 0002).
- The shim is intentionally partial. The IdP `server` adapter, ECP/PAOS,
  artifact resolution, virtual organisations, and pysaml2's on-disk attribute-map
  files are not provided; attribute conversion uses
  `attribute_map.AttributeConverterSet.with_default_maps()` instead. Anything
  outside the implemented SP surface must be addressed before a consumer that
  relies on it can migrate.
- Signed HTTP-Redirect LogoutRequests and LogoutResponses require `SigAlg`,
  `Signature`, and the exact percent-encoded signed query. The unmodified
  djangosaml2 logout view forwards only the decoded SAML parameter and binding,
  so that specific flow needs an adapter change or the POST/enveloped binding;
  the shim cannot safely reconstruct discarded signature input.
- Behavioural divergences from pysaml2 are deliberate and documented: malformed
  native session encodings fail closed; assertion/logout replay is enforced;
  LogoutResponses must correlate with stored state; and Redirect signatures are
  verified only from the exact signed query string. They are pinned by
  `tests/test_compat_saml2.py`, including djangosaml2's import, metadata,
  assertion-confirmation, scoping, cache, and state contracts.
- Full end-to-end acceptance is the existing eduID SP test suites, run in the
  eduid-developer environment; the in-repo tests verify the pygamlastan-facing
  core without the Flask/Mongo stack.

This is a new surface; it does not supersede an earlier ADR.
