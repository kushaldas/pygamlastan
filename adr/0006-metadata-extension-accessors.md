# ADR 0006: Metadata extension accessors (MDUI, algsupport, requested attributes)

- **Status:** Accepted
- **Date:** 2026-06-28
- **Deciders:** pygamlastan maintainers

## Context

The eduID IdP reads several SP-metadata signals pysaml2 exposes via
`idp.metadata.*`: the registration authority, entity attributes (entity
categories and `subject-id:req`), the SP's requested attributes, the SP's
display metadata (`mdui:UIInfo`, for the consent screen), and the SP's supported
signing/digest algorithms (`mdmd:alg`). At the start of this work gamlastan
parsed only `mdrpi:RegistrationInfo` and `mdattr:EntityAttributes` (via
`MdExtensions`); `mdui:UIInfo` and `alg:SigningMethod`/`alg:DigestMethod` were
**not parsed at all**, and there was no binding for any of these on the Python
`EntityDescriptor`. (A generic SSO error-response builder was assumed missing but
already existed upstream as `profiles::sso::idp::create_error_response`.)

Two decisions: what to add upstream in gamlastan, and how to shape the Python
surface.

## Decision

**Upstream gamlastan (done first, per the migration plan):** extend the existing
`MdExtensions` parser - the established "structured accessors over raw Extensions
XML, fail-soft, via `parse_secure`" pattern - rather than introduce a parallel
parser. `MdExtensions` now also collects `mdui:UIInfo` (`UiInfo` /
`LocalizedText` / `UiLogo`) and `alg:SigningMethod` / `alg:DigestMethod`
(`signing_methods` / `digest_methods` / `supported_algorithms()`).
`EntityDescriptor` gains `sp_ui_info()` / `idp_ui_info()` (which look at the
matching role descriptor's `Extensions` first, then entity-level) and
`supported_algorithms()` (aggregated across the entity and SSO roles).

A subtlety surfaced and was fixed upstream: role-level `Extensions` are captured
as a raw fragment whose `mdui:` / `alg:` prefixes are declared on an ancestor
(the `EntityDescriptor`) that the fragment does not include. `MdExtensions::parse`
now declares those prefixes on its synthetic parse root, so such fragments
resolve instead of failing soft to empty. This matches how the parser already
handles `mdrpi` / `mdattr`.

**Python binding:** `metadata.EntityDescriptor` exposes `registration_authority`
(property), `entity_categories()`, `entity_attribute_values(name)`,
`entity_attributes()`, `supported_algorithms()`, `ui_info(role="sp")` (returning
a bound `UiInfo` / `UiLogo`), and `requested_attributes(acs_index=None)`. The
last returns the SP's `(required, optional)` requested attributes as
`list[core.Attribute]` - exactly the shape
`idp.ReleasePolicy.filter`'s `required` / `optional` parameters take, so metadata
requirements flow straight into attribute release without binding the metadata
`RequestedAttribute` type (consistent with ADR 0005). `UiInfo`'s localized fields
are surfaced as `list[(lang, value)]` tuples rather than a bound localized-string
type, keeping them trivially consumable from Python.

`profiles.create_error_response(idp_entity_id, acs_url, status_code, ...)` binds
the existing upstream builder, constructing the `Status` from a status-code URI
string plus optional message (the same approach as the logout error builder in
ADR 0004, since `core.Status` is not Python-constructible).

## Consequences

### Positive

- eduID's IdP can read every SP-metadata signal it needs - registration
  authority, entity categories / `subject-id:req`, requested attributes, UIInfo,
  supported algorithms - and build error responses, from Python.
- MDUI and algorithm-support parsing now exists in gamlastan for all consumers,
  following the existing fail-soft `MdExtensions` design; the namespace-resolution
  fix makes role-level extension parsing robust against real-world metadata that
  declares prefixes on the root.
- `requested_attributes` composes directly with `ReleasePolicy.filter`.

### Negative / costs

- `MdExtensions::parse` resolves a fixed set of prefixes (`md`, `mdrpi`,
  `mdattr`, `saml`, `mdui`, `alg`) on its synthetic root; a metadata document
  that uses a non-standard prefix for one of these namespaces without declaring
  it on the captured fragment would still fail soft. This is an accepted,
  pre-existing limitation of the fragment-reparse design.
- UIInfo is exposed as plain tuples, not a richly typed localized-string object;
  callers do their own language selection.
