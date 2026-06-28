# ADR 0004: Single Logout (SLO) binding surface

- **Status:** Accepted
- **Date:** 2026-06-27
- **Deciders:** pygamlastan maintainers

## Context

The eduID migration (replacing pysaml2 with pygamlastan) needs Single Logout on
both the SP and IdP side: pysaml2's `Saml2Client.global_logout`,
`parse_logout_request_response`, `handle_logout_request`, and the IdP's
`parse_logout_request` / `create_logout_response`. gamlastan implements the full
SLO profile in `profiles::logout`, but none of it was bound to Python.

`profiles::logout` offers more than a thin request/response pair: it has a
transport-agnostic state machine, `SpLogoutOrchestrator`, that models
SP-initiated logout across every entity holding a session for the principal
(the equivalent of pysaml2's `global_logout`/`do_logout`/`handle_logout_response`
loop). It also exposes `create_idp_propagation_request`, which fans a logout out
to session participants but depends on the `profiles::session`
`SessionParticipant` / session-store types.

Decisions to make for the binding surface:

1. How to expose the orchestrator (a stateful, mutating object) under the
   binding's otherwise "frozen, owned-only" convention.
2. Whether to bind `create_idp_propagation_request` (and therefore the session
   module) now.
3. How to let Python build a `LogoutResponse` with a non-success status, given
   that the bound `core.Status` has no Python constructor.

## Decision

Add a top-level `pygamlastan.logout` module (sibling of `core`, `profiles`,
`idp`), registered in `lib.rs`.

1. **Orchestrator as a mutable `#[pyclass]`.** `SpLogoutOrchestrator` is bound as
   a non-`frozen` class wrapping the owned gamlastan state machine, with
   `add_target` / `next_request` / `handle_response` / `mark_failed` /
   `target_state` / `is_complete` / `progress`. This is the one place the binding
   holds mutable Rust state behind a Python object; it is single-threaded use per
   instance (no `Send`/`Sync` guarantee is needed because it is not `frozen` and
   is not shared). The builder method `with_reason` is folded into an optional
   `reason` constructor argument, since consuming-`self` builders do not map to
   Python.

2. **Defer `create_idp_propagation_request`.** It is intentionally not bound yet:
   it pulls in the `profiles::session` `SessionParticipant`/session-store surface,
   a separate module the SP-side flow does not need. SP-driven logout is fully
   covered by the orchestrator, and the IdP builds responses with the helpers
   here. Binding the session module is tracked as later work.

3. **Status-by-code response builders instead of a `Status` constructor.**
   Rather than make `core.Status` constructible from Python (a broader change),
   the module exposes three response builders mirroring the gamlastan
   convenience functions: `create_logout_response_success`,
   `create_logout_response_partial`, and `create_logout_response_error(...,
   status_code, status_message=None)`. The error builder takes a status-code URI
   string (e.g. `core.STATUS_RESPONDER`), which covers the IdP's needs without a
   mutable `Status` object crossing the boundary.

Helper types `LogoutTarget`, `PendingLogoutRequest`, `LogoutResponseOutcome`,
`TargetLogoutState`, and `LogoutPropagationResult` are bound as frozen wrappers
following the established per-module pattern. `TargetLogoutState` (a Rust enum
with data) is surfaced as a frozen object with a `kind` string plus optional
`request_id` / `reason` getters, avoiding a Python enum class for a four-state
value. `validate_logout_request` is bound as a function that raises
`SamlProfileError` on an invalid or expired request.

## Consequences

### Positive

- eduID's SP `global_logout` loop and the IdP's response generation are
  expressible from pure Python, with the orchestrator enforcing the anti-spoofing
  issuer-match check on each correlated response.
- The binding stays within its owned-only convention except for the one
  deliberately-mutable orchestrator, which is documented as single-instance use.
- No premature binding of the session module; the surface stays minimal.

### Negative / costs

- IdP-propagated logout (one IdP fanning out to many SPs) is not yet available
  from Python; it waits on a future `profiles::session` binding. SP-initiated
  logout (the eduID SP case) is fully covered.
- A caller who needs a status code the error builder does not anticipate must use
  one of the provided URIs; there is no general Python-constructed `Status`. This
  is acceptable for the logout surface and can be revisited if a broader
  `Status` constructor is added to `core`.
