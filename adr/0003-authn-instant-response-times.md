# ADR 0003: Expose `authn_instant` separately from the issue instant

- **Status:** Accepted
- **Date:** 2026-06-27
- **Deciders:** pygamlastan maintainers

## Context

gamlastan 0.6.0 split the single `now: DateTime<Utc>` argument of the IdP
response builders into a `ResponseTimes { issue_instant, authn_instant }` value
(gamlastan ADR 0025, issue #15). SAML distinguishes:

- **`IssueInstant`** — when the Response/Assertion document is generated. Also
  drives `Conditions/@NotBefore` and every `NotOnOrAfter`.
- **`AuthnStatement/@AuthnInstant`** — when the principal actually authenticated
  to the IdP.

When an IdP reuses an existing SSO session instead of re-prompting, the principal
authenticated *earlier* than the response is generated. Collapsing both to a
single `now` over-reports authentication freshness to SPs that enforce it via
`ForceAuthn`, `RequestedAuthnContext`, or a max-age policy — a freshness-spoofing
weakness, not just a cosmetic inaccuracy.

The pygamlastan bindings `profiles.create_response` and
`create_unsolicited_response` previously took a single `now=None` argument and
passed it straight to the upstream builder. The upstream signature change forced
a decision about the Python surface.

Options considered:

- **A. Mirror upstream literally:** expose a `ResponseTimes` Python class and
  require callers to construct it. Rejected: heavier API for the common case, and
  it makes the two `datetime`s easy to transpose at a Python call site (the very
  thing upstream's named-field struct exists to prevent).
- **B. Keep a single `now` and silently set `authn_instant = now`.** Rejected:
  re-introduces the freshness-spoofing footgun for reused sessions and gives
  callers no way to report the real authentication time.
- **C. Keep `now` as the issue instant and add an optional `authn_instant`,**
  defaulting `authn_instant` to `now` when omitted. The binding builds the
  `ResponseTimes` value internally.

## Decision

Adopt **C**. Both `create_response` and `create_unsolicited_response` gain an
optional `authn_instant: datetime | None = None` parameter alongside the existing
`now`:

- `now` (default: current wall clock) → `issue_instant`.
- `authn_instant` (default: `now`) → `AuthnStatement/@AuthnInstant`.

The binding constructs `ResponseTimes { issue_instant, authn_instant }` from
these. Keeping two flat keyword arguments (rather than a `ResponseTimes` wrapper)
keeps the common fresh-login call a one-liner while still letting a caller report
a real, earlier authentication time.

This is a backward-compatible addition: every existing call that omits
`authn_instant` collapses both instants to `now`, exactly the previous behaviour
(`ResponseTimes::at(now)` upstream).

The `examples/django-idp` `_issue()` view demonstrates the intended pattern by
passing `request.user.last_login` so a reused session reports its true
authentication time.

## Consequences

### Positive

- IdPs can report authentication freshness honestly; the freshness-spoofing
  weakness for reused sessions is fixable from pure Python.
- No breakage for existing callers; the default reproduces prior behaviour.
- The common case (fresh login) stays a single positional/`now` call.

### Negative / costs

- The Python API diverges slightly in shape from upstream's `ResponseTimes`
  struct (two keyword args vs one value object). Accepted: the two-arg form is
  more ergonomic for Python and the binding owns the mapping.
- A caller who wants honest freshness must remember to pass `authn_instant` for
  reused sessions; the default cannot detect "this was a reused session" on its
  own. Documented in the security guide and the IdP example.
