# ADR 0002: Route all untrusted XML through `parse_secure`

- **Status:** Accepted
- **Date:** 2026-06-27
- **Deciders:** pygamlastan maintainers

## Context

pygamlastan parses attacker-controlled XML at several entry points: the
`xml.parse_*` functions (Response, AuthnRequest, Assertion, LogoutRequest,
LogoutResponse), the `metadata.parse_entity` / `parse_entities` functions
(remote/published metadata is attacker-influenced), and the internal parse inside
`profiles.process_response_verified` (so the bytes that are signature-verified are
the bytes that are parsed).

Through 0.1.x these all called `uppsala::parse` directly. That left two classic
XML attack classes reachable before any SAML-level processing:

1. **XXE / entity smuggling.** A document with a DTD (`<!DOCTYPE …>`) and internal
   or external entity declarations could expand entities into the parsed SAML
   tree, exfiltrate files, or smuggle structure past wrapping/validation checks.
2. **Resource exhaustion.** Billion-laughs / quadratic entity amplification and
   deeply nested elements could exhaust memory or the stack.

gamlastan 0.6.0 (with uppsala 0.5) introduced `gamlastan::xml::parse_secure`, a
drop-in replacement for `uppsala::parse` that (a) rejects any DTD-bearing
document outright and (b) inherits uppsala 0.5's fail-closed resource limits
(element nesting depth 128, entity-expansion byte budget 1 MiB, entity nesting
depth 256). Upstream migrated every inbound parse site to it (gamlastan ADR 0023
/ 0024). The binding had to make the matching decision for the parse sites *it*
owns.

Options considered:

- **A. Expose both `parse` and `parse_secure` to Python** and let integrators
  choose. Rejected: the unsafe option is a footgun with no legitimate use for
  inbound SAML, and "choose the secure parser" is exactly the decision a binding
  should make for the caller.
- **B. Add a per-call `harden=True/False` flag.** Rejected: same footgun, plus it
  invites insecure defaults and complicates the API.
- **C. Always use `parse_secure` for every untrusted parse site; never expose the
  raw parser.** Trusted, library-internal round-trips (serialize-then-reparse)
  may continue to use the plain parser inside Rust, but no Python-reachable path
  does.

## Decision

Adopt **C**. Every Python-reachable parse entry point calls
`gamlastan::xml::parse_secure`. The raw `uppsala::parse` is not exposed through
any binding function. A DTD-bearing or over-budget document surfaces as
`SamlXmlError`, consistent with other malformed-input handling.

Because legitimate SAML messages never carry a DTD, rejecting all DTD-bearing
documents has no false-positive cost and categorically removes the XXE entry
point. The resource limits are uppsala defaults, not tunable from Python, keeping
the safe behaviour non-overridable.

## Consequences

### Positive

- XXE / external-entity / entity-smuggling is closed for every inbound document,
  with no opportunity for an integrator to opt out by accident.
- Billion-laughs and deep-nesting amplification are bounded before SAML
  processing runs.
- The guarantee is uniform across protocol messages, metadata, and the
  verify-internally response path.

### Negative / costs

- A deployment that (incorrectly) relied on DTDs in SAML messages would now be
  rejected. This is intended; such input is non-conformant and unsafe.
- The resource limits are not configurable from Python. If a legitimate document
  ever exceeds them, the fix is upstream in uppsala/gamlastan, not a binding
  knob. Accepted to keep the safe path non-overridable.

### Follow-ups

- If a real deployment needs different limits, add a configuration path upstream
  rather than exposing the raw parser here.
