# Django SAML IdP (pygamlastan example)

A small, **self-contained SAML 2.0 Identity Provider** built with
[Django 6.0](https://www.djangoproject.com/) and
[`pygamlastan`](../../). It demonstrates the IdP side of the Web Browser SSO
profile: it parses an SP's metadata, processes incoming `AuthnRequest`s,
authenticates the user against Django's auth, and returns a **signed** SAML
assertion over the HTTP-POST binding.

It has **no local SP database**: Service Providers are resolved at request time
from local metadata files or an MDQ service (see
[Service Provider metadata](#service-provider-metadata)).

> Built for learning and integration testing. The defaults (demo accounts, a
> self-signed key, a dev secret key) are **not** production-ready - see
> [Security notes](#security-notes).

## What it does

- Publishes IdP metadata at `/idp/metadata` (entityID, both SSO bindings, signing
  cert, and a registered `errorURL` per SWAMID Tech 5.1.13 - the `/idp/error` page).
- Accepts `AuthnRequest`s at `/idp/sso/` over **HTTP-Redirect** (GET) and **HTTP-POST**.
- Looks the SP up by issuer, validates the request against the SP's metadata
  (`process_authn_request`), and resolves the AssertionConsumerService.
- Authenticates the user (Django login), then builds an assertion with a small
  attribute set (`displayName`, `uid`, `givenName`, `sn`, `mail`, and the scoped
  `eduPersonPrincipalName` / `eduPersonScopedAffiliation`) and the requested NameID format
  (transient / persistent / email).
- **Signs the assertion** (enveloped XML-DSig, `WantAssertionsSigned`-friendly)
  and POSTs it back to the SP's ACS via a self-submitting form.

All SAML work lives in [`idp/saml_logic.py`](idp/saml_logic.py); the Django views
([`idp/views.py`](idp/views.py)) stay thin.

## Quick start (Docker Compose + Caddy)

> **Orchestration moved up a level.** The Docker Compose file, Caddy config,
> `.env`, and `justfile` now live in [`examples/`](../) and run this IdP together
> with the [`django-sp`](../django-sp/) example behind a **single** Caddy. Run
> the stack from there - see [`examples/README.md`](../README.md):
>
> ```console
> cd ..            # the examples/ directory
> cp .env-example .env
> just wheel       # only until pygamlastan is on PyPI
> just up          # certs, build, start, and link IdP <-> SP metadata
> ```
>
> The recipe names below (`just add-sp`, `just swamid-cert`, ...) and the
> `./data/caddy` TLS path describe the previous standalone layout; the equivalents
> now live in the top-level `justfile` (`just link`, `just swamid-cert`, certs in
> `examples/certs/`). The rest of this document still describes the IdP itself.

Prerequisites: Docker (with Compose), [`just`](https://github.com/casey/just),
and [`mkcert`](https://github.com/FiloSottile/mkcert) (for locally-trusted TLS).
Until `pygamlastan` is on PyPI, also Rust + `maturin` for the one-time wheel build.

```console
# 0. configure: copy the template and set IDP_DOMAIN (.env is gitignored).
#    The template uses the SWAMID QA MDQ and a placeholder domain.
cp .env-example .env

# 1. (only until pygamlastan is on PyPI) build a wheel into ./wheels
just wheel

# 2. generate keys, the MDQ signing cert, and mkcert TLS certs, then bring up
just up

# 3. open the IdP at https://${IDP_DOMAIN}/  and  /idp/metadata
```

`just up` generates `./data/idp_key.pem` + `idp_cert.pem`, fetches the SWAMID
signing cert, creates **mkcert** TLS certs for `IDP_DOMAIN` in `./data/caddy`,
builds the image, and starts two containers: **idp** (Django + gunicorn) and
**caddy** (TLS + reverse proxy). The SQLite DB (users and sessions only - no SP
data) and keys persist in `./data`.

Caddy serves HTTPS using the mkcert cert/key (no Let's Encrypt), so it works for
any local domain. For a custom `IDP_DOMAIN` like `idp.gamlastan.sverige`, point
it at your host so the browser can reach it:

```console
echo "127.0.0.1 idp.gamlastan.sverige" | sudo tee -a /etc/hosts
```

#### Demo credentials

Created on first boot:

| Who   | Username | Password    | Where           |
|-------|----------|-------------|-----------------|
| Users | `angela`, `pamela`, `sandra`, `monica`, `erica`, `rita`, `tina`, `jessica` | `gamlastan` | `/idp/login/` |
| Admin | `admin`  | `admin`     | `/admin/`       |

### TLS certificates

`just tls` (run as part of `just up`) uses **mkcert** to create a locally-trusted
cert/key for `IDP_DOMAIN` in `./data/caddy`, and Caddy serves them via an explicit
`tls` directive (no ACME). Delete `./data/caddy` and re-run `just tls` to
regenerate, e.g. after changing `IDP_DOMAIN`.

For a public deployment with a real CA instead, drop the `tls` line from the
[`Caddyfile`](Caddyfile) (Caddy then does automatic Let's Encrypt for a public
`IDP_DOMAIN` that resolves to the host with ports 80/443 open).

## Service Provider metadata

There is **no local SP database**. When an SP sends an `AuthnRequest`, the IdP
resolves its metadata from two sources, tried in order:

1. **Local files** - signed/self-contained SP metadata XML placed in the metadata
   dir (`./data/metadata`, mounted `/data/metadata`). The SP's own keys are
   embedded in the file, so these are **trusted as provided** (you put them on
   disk) and indexed by entityID in memory at startup. Add one with:

   ```console
   just add-sp /path/to/sp-metadata.xml     # copies into ./data/metadata, reloads
   just reload-metadata                      # after editing files there
   ```

2. **MDQ** - if `SAML_IDP_MDQ_URL` is set, an unknown entityID is fetched on
   demand from a Metadata Query server and **mandatorily signature-verified**
   against `SAML_IDP_METADATA_CERT` before it is trusted.

The bundled `.env` points MDQ at SWAMID and uses its signing certificate; fetch
the cert (done automatically by `just up`) with:

```console
just swamid-cert     # -> ./data/swamid-signing.pem (SAML_IDP_METADATA_CERT)
```

To use **only** local files, leave `SAML_IDP_MDQ_URL` empty in `.env` and add SPs
with `just add-sp`. The SP must, in turn, trust this IdP - hand it
`https://<host>/idp/metadata`.

> **Why the split?** Local files are self-contained (the SP keys are in them) and
> trusted because you placed them; MDQ is remote, so its responses are signature-
> verified against the federation's metadata signing certificate. The cert is
> mandatory whenever MDQ is enabled.

## Common tasks (`just`)

```
just              # list recipes
just up           # keygen + swamid-cert + tls + build + start (idp + caddy)
just tls          # mkcert TLS cert/key for $IDP_DOMAIN -> ./data/caddy
just down         # stop
just logs         # follow logs
just swamid-cert  # fetch the SWAMID metadata signing cert (for MDQ)
just add-sp FILE  # add a local SP from its metadata XML (no DB, no MDQ)
just reload-metadata   # restart to reload ./data/metadata
just metadata     # print IdP metadata through Caddy
just shell        # Django shell in the container
just keygen       # (re)generate IdP key/cert in ./data if missing
just wheel        # build+stage a pygamlastan wheel in ./wheels
```

## Configuration

Set via `.env` (copy [`.env-example`](.env-example); read automatically by docker
compose) and [`docker-compose.yml`](docker-compose.yml).

| Variable | Default | Purpose |
|----------|---------|---------|
| `IDP_DOMAIN` | set in `.env` (e.g. `idp.gamlastan.sverige`) | Public hostname; drives Caddy TLS and the IdP base URL |
| `SAML_IDP_BASE_URL` | `https://${IDP_DOMAIN}` | Base for entityID and endpoints |
| `SAML_IDP_ENTITY_ID` | `${BASE_URL}/idp/metadata` | IdP entityID |
| `SAML_IDP_KEY` / `SAML_IDP_CERT` | `/data/idp_{key,cert}.pem` | Signing key / cert |
| `SAML_IDP_NAMEID_SECRET` | demo value | Secret for opaque persistent NameIDs |
| `SAML_IDP_SUPPORT_EMAIL` | _(unset)_ | Contact shown on the `/idp/error` page (errorURL target) |
| `SAML_IDP_METADATA_DIR` | `/data/metadata` | Local SP metadata files, loaded at startup (trusted) |
| `SAML_IDP_MDQ_URL` | SWAMID (in `.env`) | MDQ base URL for on-demand SP resolution |
| `SAML_IDP_METADATA_CERT` | SWAMID cert (in `.env`) | PEM cert to verify MDQ metadata (required with MDQ) |
| `DJANGO_SECRET_KEY` | dev value | Django secret key |
| `DJANGO_ALLOWED_HOSTS` | `${IDP_DOMAIN},localhost,idp` | Allowed hosts |
| `DJANGO_DEBUG` | `0` | Debug mode |
| `DEMO_PASSWORD` | `gamlastan` | Shared password for the seeded demo users |
| `DJANGO_ADMIN_USERNAME` / `DJANGO_ADMIN_PASSWORD` | `admin` / `admin` | Seeded admin |

> For purely local testing set `IDP_DOMAIN=localhost` in `.env` so Caddy serves
> HTTPS with its local CA (a public domain triggers a real Let's Encrypt attempt
> that needs the name to resolve to your host).

## Local development (without Docker)

```console
uv venv
uv pip install --find-links wheels django==6.0.6 pygamlastan cryptography gunicorn whitenoise
export DJANGO_DEBUG=1 SAML_IDP_BASE_URL=http://localhost:8000
python manage.py idp_keys
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```

(`--find-links wheels` lets a locally-built `pygamlastan` wheel satisfy the
dependency; once it is on PyPI you can drop that flag.)

## How the SAML flow works

```
SP ──AuthnRequest (Redirect/POST)──▶ /idp/sso/
                                       │  decode + parse + process_authn_request(SP metadata)
                                       │  stash request in session
                                       ▼
                              not logged in? ──▶ /idp/login/ ──▶ authenticate
                                       │
                                       ▼  build assertion → sign (enveloped XML-DSig)
SP ◀──auto-POST SAMLResponse────── self-submitting form (HTTP-POST binding)
```

The assertion is signed with the IdP key so the SP can verify it against the
certificate in the IdP metadata. NameID format follows the SP's `NameIDPolicy`
(transient by default; persistent uses an opaque per-SP eduPersonTargetedID).

## Security notes

This example optimises for a working demo. Before any real use:

- Replace the demo accounts and set a strong `DJANGO_SECRET_KEY`.
- Replace the self-signed IdP key with your real signing key/cert, kept off the
  image (mount it, or use the PKCS#11/HSM path - see the main project's
  [signing guide](../../docs/guides/signing.rst)).
- This IdP does **not** require signed `AuthnRequest`s
  (`WantAuthnRequestsSigned="false"`); enable and verify request signatures if
  your threat model needs them (the SP signing certs are in the resolved metadata).
- Review attribute release and NameID policy for your privacy requirements.
- MDQ responses are signature-verified against `SAML_IDP_METADATA_CERT` (this is
  enforced - the IdP refuses an SP whose signature fails). Local metadata files
  are trusted as provided, so only place files you obtained from a trusted source.
- Put it behind your real TLS hostname (`IDP_DOMAIN`) so Caddy issues a trusted
  certificate.
