# Architecture Decision Records

This directory holds significant, hard-to-reverse design decisions for
pygamlastan, in the lightweight ADR format (Status / Context / Decision /
Consequences).

Each record is immutable once accepted; a later decision that changes course is
added as a new record that supersedes the old one (note the supersession in both
records).

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-profile-extension-surface.md) | Extension surface for building new SAML profiles | Accepted |
| [0002](0002-parse-secure-untrusted-xml.md) | Route all untrusted XML through `parse_secure` | Accepted |
| [0003](0003-authn-instant-response-times.md) | Expose `authn_instant` separately from the issue instant | Accepted |
| [0004](0004-single-logout-binding.md) | Single Logout (SLO) binding surface | Accepted |
| [0005](0005-attribute-release-policy-surface.md) | Attribute-release policy and entity-category binding surface | Accepted |
| [0006](0006-metadata-extension-accessors.md) | Metadata extension accessors (MDUI, algsupport, requested attributes) | Accepted |
