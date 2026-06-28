# Django SAML SP (pygamlastan example)

A small, **self-contained SAML 2.0 Service Provider** built with
[Django 6.0](https://www.djangoproject.com/) and [`pygamlastan`](../../). It
demonstrates the SP side of the Web Browser SSO profile: it builds and sends an
`AuthnRequest`, consumes the IdP's signed `Response` at its ACS, and **displays
every attribute the IdP released**.

It has **no local IdP database**: the IdP is resolved at request time from a
local metadata file or an MDQ service (signature-verified).

> Built for learning and integration testing. The defaults (a self-signed key, a
> dev secret key) are **not** production-ready.

## What it does

- Publishes SP metadata at `/sp/metadata`: an `SPSSODescriptor` with the ACS
  (HTTP-POST), signing + encryption keys, requested attributes
  (`AttributeConsumingService`), `mdui:UIInfo`, `Organization`, technical/support/
  security `ContactPerson`s, and the REFEDS **Research & Scholarship** entity
  category (which drives attribute release at R&S-supporting IdPs).
- Starts SSO at `/sp/login/`: with no fixed IdP it sends the user to the
  **discovery service** (`SAML_SP_DISCOVERY_URL`) to choose one; the DS returns
  to `/sp/disco/` with the chosen `entityID`, which is resolved from the SWAMID
  QA MDQ. (Set `SAML_SP_IDP_ENTITYID` to skip discovery and always use one IdP.)
  It then builds an `AuthnRequest` and redirects (HTTP-Redirect) to the IdP.
- Consumes the `Response` at `/sp/acs/` (HTTP-POST) with the safe
  **`profiles.process_response_verified`**: it verifies the XML-DSig over the
  exact response bytes with the IdP's signing cert and feeds only the
  cryptographically verified IDs into validation.
- Shows the `NameID`, issuing IdP, authn context, and the full released
  attribute set on `/sp/`.

All SAML work lives in [`sp/saml_logic.py`](sp/saml_logic.py); the Django views
([`sp/views.py`](sp/views.py)) stay thin. The IdP is resolved by
[`sp/idp_resolver.py`](sp/idp_resolver.py).

## Running it

This SP runs as part of the local federation orchestrated from
[`examples/`](../): see [`examples/README.md`](../README.md). In short:

```console
cd ..            # the examples/ directory
cp .env-example .env
just wheel       # only until pygamlastan is on PyPI
just up          # certs, build, start, and link IdP <-> SP metadata
```

Open `https://${SP_DOMAIN}/`, click **Log in**, authenticate at the IdP as
`angela` / `gamlastan`, and the released attributes appear.

## Configuration

All settings are environment variables (set in `../.env`). The important ones:

| Variable | Purpose |
| --- | --- |
| `SAML_SP_IDP_ENTITYID` | optional fixed IdP; **leave empty to use discovery** |
| `SAML_SP_DISCOVERY_URL` | discovery service (SWAMID QA: `https://ds.qa.swamid.se/ds/`) |
| `SAML_SP_MDQ_URL` | MDQ base for resolving IdP metadata (e.g. `https://mds.swamid.se/qa/`) |
| `SAML_SP_METADATA_CERT` | federation signing cert (mandatory when MDQ is set) |
| `SAML_SP_METADATA_DIR` | local IdP metadata files (tried before MDQ, trusted as provided) |
| `SAML_SP_DISPLAY_NAME`, `SAML_SP_DESCRIPTION` | shown by IdP discovery (`mdui`) |
| `SAML_SP_ORG_*` | `Organization` block |
| `SAML_SP_TECHNICAL_EMAIL`, `SAML_SP_SUPPORT_EMAIL`, `SAML_SP_SECURITY_EMAIL` | contacts (required by SWAMID) |

## Registering this SP in SWAMID QA

SWAMID QA does not auto-trust arbitrary metadata; entities are **registered**
through SWAMID's operations tooling, after which the metadata is re-signed into
the QA aggregate / served from the QA MDQ. To register this SP:

1. **Fill in real values** in `../.env` before generating metadata: a resolvable
   `SAML_SP_*` display name, organization, and the three contact emails
   (technical, support, and a REFEDS **security** contact are required by SWAMID
   Tech). A registered, resolvable `entityID` (https URL) is also required.
2. **Export the metadata**: `just sp-metadata > sp.xml` (from `examples/`).
3. **Submit it** via the SWAMID metadata registration process (the SWAMID
   operations workflow / Metadata Registration Practice Statement). SWAMID adds
   the `mdrpi:RegistrationInfo` and signs the entity into the QA feed.
4. Once registered, QA IdPs can send assertions to this SP, and you can point
   `SAML_SP_IDP_ENTITYID` at a SWAMID QA IdP (with `SAML_SP_MDQ_URL` +
   `SAML_SP_METADATA_CERT` set to the QA MDQ and signer) to log in through it.

The REFEDS R&S entity category is already advertised in the metadata, so
R&S-supporting IdPs will release the core attribute set without per-SP rules.

### Discovery (choosing an IdP) and re-publishing

In federation mode the SP sends users to a discovery service to pick an IdP. The
SP advertises a `<idpdisc:DiscoveryResponse>` endpoint (`/sp/disco/`) in its
metadata; the SeamlessAccess discovery service (SWAMID QA:
`https://ds.qa.swamid.se/ds/`) **validates the `return` URL against that
endpoint**. If you registered the SP before this endpoint existed, the DS shows
*"Unable to verify returning website"* - **re-export and re-publish** the
metadata (`just sp-metadata > sp.xml`, then submit it again) so the
`DiscoveryResponse` is in the signed QA feed. The `return` URL and the
`DiscoveryResponse` Location must match exactly (`https://<sp>/sp/disco/`).

## Security notes

- The session cookie is `SameSite=None; Secure` so it survives the IdP's
  cross-site POST to the ACS (the request-id binding depends on it). The stack
  always runs behind Caddy TLS.
- Every inbound SAML Response and every resolved IdP metadata document is parsed
  through the hardened `parse_secure` path: a DTD/`<!DOCTYPE>` is rejected before
  any further handling (closing XXE / entity smuggling), and uppsala's
  fail-closed resource limits (nesting depth, entity-expansion budget) bound
  billion-laughs and deep-nesting amplification. The SP never touches the raw
  parser, so this protection cannot be accidentally bypassed.
- The SP trusts an IdP's assertion only after `process_response_verified`
  succeeds against the signing cert in the **resolved IdP metadata**. Local
  metadata files are trusted as provided; MDQ metadata is signature-verified.
- `process_response_verified` is the *only* safe entry point: it performs the
  XML-DSig verification internally over the exact received bytes and feeds only
  the cryptographically verified reference IDs into validation. The lower-level
  `process_response` / `security.validate_response` trust caller-supplied
  `verified_signed_ids`, so passing those without real verification is an
  authentication bypass - the example deliberately never does this.
- A replay cache and a persistent-NameID store are passed to
  `process_response_verified` (the hardened library requires the latter whenever
  a response carries a persistent NameID, to detect NameID reassignment). Both
  are in-memory and fail closed - back them with a shared store (database/Redis)
  for multi-process or production use.
