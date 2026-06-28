# ADR 0005: Attribute-release policy and entity-category binding surface

- **Status:** Accepted
- **Date:** 2026-06-28
- **Deciders:** pygamlastan maintainers

## Context

The eduID migration needs the IdP attribute-release engine: which attributes
(and values) are released to each SP, driven by entity categories, the SP's
requested attributes, per-SP/registration-authority overrides, and the
subject-id profile. gamlastan implements all of this in `idp::policy`
(`ReleasePolicy`, `PolicyEntry`, `SignTargets`) and `idp::entity_category`
(`OwnedEntityCategoryRule/Policy`, the shipped SWAMID/REFEDS/… policies,
`SubjectIdReq`), but none of it was bound to Python. The upstream API uses
several types the binding does not otherwise expose - `RequestedAttribute`,
`SpSsoDescriptor`, `SubjectIdReq`, `TimeDelta`, `&'static` shipped policies - so
the Python surface needs deliberate shaping.

Questions:

1. How to pass the SP's *requested* attributes into `filter` without binding the
   metadata `RequestedAttribute` / `SpSsoDescriptor` types.
2. How to represent `SubjectIdReq` (a four-value enum) in Python.
3. How to expose the shipped `&'static` entity-category policies and let a
   developer define custom ones.
4. How to map `PolicyEntry`'s consuming-`self` builder and `TimeDelta` lifetime.

## Decision

Bind the engine into `pygamlastan.idp` (extending that module, per the plan).

1. **`filter` takes plain `core.Attribute` lists for required/optional.** Rather
   than bind `RequestedAttribute`, the `required` and `optional` parameters are
   `list[core.Attribute]`; the binding wraps each as a `RequestedAttribute` with
   the appropriate required flag (values on the attribute still narrow the
   released values). The metadata-driven `restrict(...)` overload (which extracts
   requirements from an `SpSsoDescriptor` + ACS index) is **not** bound; a caller
   gets the SP's requested attributes from a metadata accessor and passes them to
   `filter`. This avoids binding two metadata role types for one call shape.

2. **`SubjectIdReq` is a string.** `filter` takes
   `subject_id_req: str` in `{"none", "subject-id", "pairwise-id", "any"}`
   instead of a bound enum class, and `subject_id_req_from_metadata(values)`
   returns the same strings. Strings are idiomatic in Python and avoid a
   four-instance enum class for a single parameter.

3. **Shipped policies by name; custom via owned types.** Shipped entity-category
   policies are referenced by short name (`entity_categories=["swamid"]`, and
   `EntityCategoryPolicy.shipped("swamid")`), resolved to the `&'static` upstream
   values. Developer-defined categories use bound `EntityCategoryRule` /
   `EntityCategoryPolicy` (the owned upstream variants), which can also `extend` a
   shipped policy. `PolicyEntry` merges shipped-by-name and owned policies into
   one list so both can be combined.

4. **`PolicyEntry` is an all-keyword constructor; lifetime is seconds.** The
   consuming-`self` builder is folded into one constructor with optional keyword
   arguments (the restriction-compile error surfaces as `SamlPolicyError`).
   `TimeDelta` is exposed as integer seconds (`lifetime_seconds`,
   `ReleasePolicy.lifetime_seconds`) to avoid leaking a Rust duration type.
   `ReleasePolicy` is the one mutable `#[pyclass]` here (it accumulates entries);
   the value types (`PolicyEntry`, `SignTargets`, the entity-category types) are
   frozen and `from_py_object` so they pass back into the policy by value.

`register_sp_metadata(EntityDescriptor)` reads the registration authority from
parsed SP metadata, completing the SP > registration-authority > default
resolution the eduID IdP config relies on. The standalone engine is also exposed
as `releasable_attributes(policies, sp_entity_categories, required_local_names)`.

The lower-level `filter_on_attributes` / `filter_attribute_value_assertions` /
`filter_on_demands` / `filter_on_wire_representation` helpers are not bound; the
single `filter` pipeline covers the eduID release flow.

## Consequences

### Positive

- eduID's per-SP / per-registration-authority attribute release, entity-category
  release (including developer-defined custom categories), value restrictions,
  the subject-id/pairwise-id rule, and signing decisions are all expressible from
  Python.
- The Python surface avoids binding the metadata `RequestedAttribute` /
  `SpSsoDescriptor` / `SubjectIdReq` types, keeping the call shapes small.

### Negative / costs

- A caller wanting metadata-driven `restrict` must extract the SP's requested
  attributes itself (via a metadata accessor) and pass them to `filter`; the
  one-call metadata overload is not available.
- Representing `SubjectIdReq` and shipped policies as strings trades a small
  amount of type safety (an invalid string raises at call time) for ergonomics.
- The lower-level filter helpers are unbound; if a deployment needs one it must
  be added later.
