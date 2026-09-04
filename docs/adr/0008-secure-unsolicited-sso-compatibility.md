# ADR 0008 - Secure unsolicited SSO compatibility

- **Status:** Accepted
- **Date:** 2026-09-03
- **Deciders:** pygamlastan maintainers
- **Implementation:** `src/security.rs`, `python/pygamlastan/compat/saml2/config.py`, `python/pygamlastan/compat/saml2/client.py`

## Context

gamlastan 0.9 rejects unsolicited Web SSO by default to prevent login CSRF.
PySAML2 integrations already have an established `service.sp.allow_unsolicited`
setting, while pygamlastan's direct policy surface needs to expose the matching
core control. Silently accepting when the caller omits its outstanding-request
mapping would defeat the new default; unconditionally rejecting would break
deployments that intentionally use IdP-initiated SSO.

## Decision

1. Expose `SecurityConfig.allow_unsolicited_responses` as a normal read/write
   Python property.
2. Parse PySAML2's existing `allow_unsolicited` setting, defaulting to `False`.
3. When there is no outstanding mapping, accept only a response with no
   `InResponseTo` and only when that setting is enabled. A dangling
   `InResponseTo` never becomes an unsolicited response.
4. Continue translating correlation denial to PySAML2's
   `UnsolicitedResponse`, preserving the exception contract used by
   djangosaml2.
5. Keep the compatibility layer's existing scoped assertion and logout replay
   caches; it does not duplicate insertion through the new core logout helper.

## Consequences

- Existing PySAML2 users retain the familiar opt-in and exception names.
- Deployments relying on implicit unsolicited acceptance must add
  `allow_unsolicited = True` after confirming that login CSRF is acceptable and
  separately mitigated.
- pygamlastan's gamlastan dependency advances to 0.9 in the coordinated core
  then binding release; local verification uses a path patch until 0.9 is
  published.
