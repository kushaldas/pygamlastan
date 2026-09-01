# pygamlastan examples: a local SAML federation

Two self-contained Django apps built on [`pygamlastan`](../), wired into a small
local federation behind **one** Caddy that terminates TLS for both hostnames:

| Service | Hostname | What it is |
| --- | --- | --- |
| [`django-idp`](django-idp/) | `https://${IDP_DOMAIN}/` | SAML 2.0 **Identity Provider** |
| [`django-sp`](django-sp/) | `https://${SP_DOMAIN}/` | SAML 2.0 **Service Provider** that shows the attributes the IdP released |

Orchestration (compose, Caddy, `.env`, and the `justfile`) lives **here** at the
top of `examples/`; each app keeps only its own code, `Dockerfile`, and data dir.

## Quick start (Docker Compose + Caddy + mkcert)

Prerequisites: Docker (with Compose), [`just`](https://github.com/casey/just),
[`mkcert`](https://github.com/FiloSottile/mkcert), Rust, and `maturin`.

The example apps require `pygamlastan>=0.4.0`, the binding release aligned with
`gamlastan` 0.8.0.

```console
# 0. configure (.env is gitignored). Defaults use *.gamlastan.sverige.
cp .env-example .env

# Point the two hostnames at localhost so the browser reaches Caddy:
#   echo "127.0.0.1 idp.gamlastan.sverige sp.gamlastan.sverige" | sudo tee -a /etc/hosts

# 1. build and stage the local pygamlastan wheel, create certificates, and start
just up
```

`just up` first builds the repository's `pygamlastan` wheel into both app build
contexts, then runs `tls` (mkcert certs into `./certs/{idp,sp}`),
`swamid-cert`, and `docker compose up -d --build`. Run `just link` after the
first start to fetch each party's metadata into the other's local metadata dir
so the **local IdP and SP trust each other without SWAMID**.

Then:

1. Open the SP at `https://${SP_DOMAIN}/` and click **Log in**.
2. You are redirected to the IdP; sign in as **`angela`** / `gamlastan` (or
   `pamela`, `sandra`, ...).
3. Back at the SP you see the released attributes: `displayName`, `uid`,
   `givenName`, `sn`, `mail`, `eduPersonPrincipalName`,
   `eduPersonScopedAffiliation`.

## Useful recipes

```console
just logs sp          # follow one service's logs (or: just logs)
just sp-metadata      # print SP metadata (submit this to SWAMID to register)
just idp-metadata     # print IdP metadata
just link             # re-exchange metadata after a config change
just restart sp       # restart one service
just down             # stop everything
```

## How the two trust each other

- **Locally** (`just link`): each app's metadata is fetched over HTTPS and saved
  as a trusted local file in the other app's `data/metadata/` dir. No federation
  needed.
- **Via SWAMID QA**: the IdP resolves SPs from the SWAMID QA MDQ
  (`SAML_IDP_MDQ_URL`), signature-verified against the QA signer cert. To use a
  SWAMID QA IdP from the SP instead of the local one, set `SAML_SP_MDQ_URL` +
  `SAML_SP_METADATA_CERT` and point `SAML_SP_IDP_ENTITYID` at a QA IdP. See
  [`django-sp/README.md`](django-sp/README.md) for registering the SP in SWAMID QA.
  Both example MDQ clients configure the verifier in trusted-key, strict,
  digest-required mode and reject raw inline `KeyInfo` trust when a federation
  trust anchor is configured.

> Built for learning and integration testing. The defaults (demo accounts,
> self-signed keys, a dev secret key) are **not** production-ready.
