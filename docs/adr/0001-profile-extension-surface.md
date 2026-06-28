# ADR 0001: Extension surface for building new SAML profiles

- **Status:** Accepted
- **Date:** 2026-06-25
- **Deciders:** pygamlastan maintainers

## Context

pygamlastan is a thin PyO3 binding over the `gamlastan` 0.5.0 Rust SAML library.
A recurring question is how hard it is for downstream users (notably a SATOSA
backend replacing pysaml2) to build a **new SAML profile** on top of the binding
— Single Logout, ECP, a national eIDAS/Sweden-Connect profile, or a house
profile — without forking the Rust crate.

Surveying gamlastan against the bound surface revealed three relevant facts:

1. gamlastan already **implements** far more than pygamlastan binds: SSO (SP and
   IdP), Single Logout, ECP/PAOS, Artifact Resolution, Assertion Query, NameID
   Mapping/Management, PEFIM and the Sweden-Connect profile. pygamlastan
   originally bound only Web Browser SSO plus the session store.
2. The validation policy object, `SecurityConfig`, has 12 fields, but only 6
   were exposed as Python properties. The rest (encrypted-assertion requirement,
   `ds:Object` rejection, persistent-ID uniqueness, RelayState sanitisation, CBC
   integrity, client-address binding) could only be reached via the `new()` /
   `strict()` / `permissive()` presets.
3. gamlastan's 32-check validator runs as a **unit**. Only one check
   (`check_assertion_age`) is callable standalone; the others are private. The
   per-check *outcomes*, however, are returned as a structured result.

We also fixed an adjacent trust-coupling risk: validation previously trusted a
caller-supplied "signature verified" flag, which is an authentication-bypass
footgun if mis-wired (see the differential security review,
`DIFFERENTIAL_REVIEW_REPORT.md`).

We considered three broad directions:

- **A. Bind every gamlastan profile up front.** Maximal capability, but a large
  surface to maintain and most of it unused by early adopters.
- **B. Keep the binding minimal and tell users to drop to Rust** whenever they
  need anything beyond Web Browser SSO. Small surface, but a steep cliff that
  pushes pure-Python users into the toolchain for routine policy tweaks.
- **C. Expose the reusable *primitives* and the full policy surface, and treat
  whole-profile bindings as incremental additions** that follow a fixed pattern.

## Decision

Adopt **C**. Concretely:

1. **Expose the complete `SecurityConfig`.** All 12 fields are individual Python
   getters/setters, so a profile can express its exact policy without relying on
   presets.
2. **Thread a persistent-ID store through validation.** `validate_response`
   accepts an optional `persistent_id_store` (a Python object implementing
   `check_and_record(name_id, sp_entity_id, principal) -> bool`), wired via a
   fail-closed adapter, enabling the E78 uniqueness check from pure Python.
3. **Make individual checks usable.** Bind the one standalone check
   (`check_assertion_age`) as a free function, and make every built-in outcome
   addressable on the result (`ValidationResult.get(n)` / `.by_name(...)` /
   `.passed_checks()` / `.failures()`). Profile-specific rules are layered in
   Python on the typed response rather than injected into the Rust suite.
4. **Provide a safe, verify-internally entry point.** `process_response_verified`
   performs XML-DSig verification over the exact bytes and feeds only the
   cryptographically verified reference IDs into validation, so trust cannot be
   asserted without real crypto.
5. **Treat unbound profiles (SLO, ECP, artifact resolution, …) as Tier-3 work:**
   a thin, mechanical binding module per profile, following the existing
   per-module pattern, added on demand. Genuinely new SAML *semantics* belong
   upstream in gamlastan, not in the binding.

This yields the tiered model documented in the
[Writing a new SAML profile](../docs/guides/writing_profiles.rst) guide: Tier 1
(compose primitives, pure Python), Tier 2 (custom policy and extra checks, pure
Python), Tier 3 (add a binding module).

## Consequences

### Positive

- The common cases — SSO-shaped profiles, custom policy, custom attribute and
  NameID handling — are achievable in pure Python, no Rust toolchain.
- Policy is fully expressible; no profile is blocked by a hidden `SecurityConfig`
  knob.
- The safe verification path is the easy path, reducing the chance of an
  auth-bypass mis-integration.
- New profile bindings are additive and low-risk; the crypto/protocol logic they
  wrap already exists and is tested in gamlastan.

### Negative / costs

- The 32-check suite remains non-pluggable: profile-specific checks run as a
  second pass in Python, i.e. the response is validated by the suite and then
  inspected again. Acceptable because the typed objects and per-check outcomes
  are already in hand.
- Tier-3 profiles still require Rust and a rebuild. We accept this rather than
  binding everything speculatively.
- `check_and_record` / replay-cache adapters cross the FFI boundary per call;
  fine for request-rate SAML traffic, not a hot loop.

### Follow-ups

- Bind Single Logout flow helpers (the message types are already exposed) as the
  first Tier-3 addition when needed.
- Revisit a post-validation hook in gamlastan if layering extra checks in Python
  proves insufficient for a real profile.
