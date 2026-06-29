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
- `saml2.response.{AuthnResponse, LogoutResponse, StatusError, UnsolicitedResponse}`;
- `saml2.metadata.entity_descriptor`, `saml2.cache.Cache`,
  `saml2.s_utils.deflate_and_base64_encode`, `saml2.sigver.get_xmlsec_binary`,
  and `saml2.server` (imported at load time by shared code).

We had two questions: **how** to migrate eduID without rewriting its Flask views
and session logic, and **where** the migration code should live.

## Decision

**Provide a thin pysaml2-API-compatible facade backed by pygamlastan, and ship
it inside the pygamlastan distribution** as `pygamlastan.compat.saml2`, mirroring
the pysaml2 module layout (`client`, `config`, `ident`, `response`, `saml`,
`cache`, `metadata`, `s_utils`, `sigver`, `server`, `typing`, `attributemaps`).
Consumers migrate by swapping `from saml2 import X` for
`from pygamlastan.compat.saml2 import X`; the surrounding view/session code is
left untouched.

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
processing) and Single Logout are implemented. The IdP `server.Server` is a
Phase 2 placeholder that raises `NotImplementedError` but imports cleanly, so
shared modules that `from saml2 import server` keep loading.

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
  validation config is `SecurityConfig.strict()` with
  `require_encrypted_assertions` turned off (eduID, like most SPs, signs but does
  not encrypt assertions).
- `want_response_signed=False` (dev/test only, as eduID's test settings set it):
  responses go through `profiles.process_response` with
  `SecurityConfig.permissive()`. The unsigned path is reachable **only** when the
  settings explicitly opt out of signatures.

Solicited-response / replay protection mirrors pysaml2's SP model: the caller's
outstanding-query set is checked for the response's `InResponseTo` (an unknown
one raises `UnsolicitedResponse`), and the entry is consumed on success. The
binding-level replay cache is therefore not used here
(`unsafe_no_replay_cache=True`); a persistent-id store can be wired later for
deployments that need cross-request `persistent` NameID uniqueness.

**NameID `code`/`decode` use the shim's own encoding.** pysaml2 serialises a
NameID to a private comma-separated quoted-attribute string. That wire form never
leaves the deployment (it is stored in the user session and handed back to the
same library), so the shim uses a self-describing `pgc1:`-prefixed
base64url(JSON) encoding instead. Both ends are the shim, so only the round-trip
matters. Unlike pysaml2's lenient `decode` (which never raises and returns an
empty NameID on bad input), the shim's `decode` raises on a string it did not
produce - a corrupt or cross-library session value is surfaced rather than
silently turned into a blank subject.

**SP metadata is templated.** pygamlastan does not (yet) ship an SP-metadata
*builder*, so `metadata.entity_descriptor(config)` renders a minimal,
schema-valid `<md:EntityDescriptor>` from the configured entityID, ACS/SLO
endpoints and signing certificate (the same approach the `django-sp` example
uses), returning an object with `.to_string()` / `.to_xml()`.

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
- Behavioural divergences from pysaml2 are deliberate and documented (strict
  `decode`; signed/unsigned gating on `want_response_signed`; no binding-level
  replay cache). They are pinned by `tests/test_compat_saml2.py`, which exercises
  the AuthnRequest round-trip, the signed and unsigned response paths, Single
  Logout, NameID code/decode, and SP metadata generation.
- Full end-to-end acceptance is the existing eduID SP test suites, run in the
  eduid-developer environment; the in-repo tests verify the pygamlastan-facing
  core without the Flask/Mongo stack.

This is a new surface; it does not supersede an earlier ADR.
