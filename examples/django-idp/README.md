# Django SAML IdP (pygamlastan example)

A teaching SAML 2.0 Identity Provider using Django **6.1.3**, SQLite, and the
locally built [`pygamlastan`](../../) library. It accepts Redirect and POST
AuthnRequests and returns assertion-signed responses over HTTP POST.

Implementation of [the account-management plan](IMPLEMENTATION_PLAN.md) is in
progress. The account model, CLI bootstrap, JSON importer, password policy, and
case-insensitive username/email login are implemented. Built-in Django admin is
disabled. The custom `/idp-admin/` account-management UI is implemented, and
SMTP settings are available through environment variables. Rate-limited password
recovery uses a shared SQLite queue and a background delivery worker. Login
throttling, the persistent NameID registry, and
database SP registry are still pending.
Signed SAML Single Logout is implemented with the sibling Django SP.
Until those steps land, treat this as a local teaching example.

## Project commands and container build

Run `just` in this directory to list commands. The local `justfile` includes
dependency setup, Django management, accounts/imports, checks/tests, and image
build/run commands. `just up`, `down`, `logs`, `restart`, `tls`, `swamid-cert`,
and `link` delegate to the shared federation stack in `examples/`.

To build **`kushaldas/django-idp:0.2.0`**, install Docker, `just`, `uv`, and a
Rust toolchain with a C linker, then run:

```console
just build
```

This builds the repository's local pygamlastan wheel with maturin, stages it in
`wheels/`, and builds the image from **`debian:trixie-slim`**. It needs no local
Python virtual environment. The Dockerfile installs the staged wheel directly
and reads the application dependencies from `pyproject.toml`. Application data,
virtual environments, and `.env` secrets are excluded from the image.

Bootstrap an administrator and run the standalone image over local HTTP:

```console
just container-manage idp_user create admin --email admin@example.org --admin
just container-run
```

Open `http://localhost:8000/idp/`. The standalone container runs in the foreground;
Ctrl-C stops it, or use `just container-stop` in another terminal. Signing keys,
SQLite accounts, and sessions persist in the host's `./data` directory. One-off
commands run migrations through the entrypoint before executing their command.

```console
just container-manage idp_user set-password admin
just container-manage idp_user set-admin alice --enable
just container-manage check
```

For a container JSON import, place the file in `data/users.json`, then run
`just container-manage idp_import_users /data/users.json`. Generated passwords
are printed once, so keep the terminal output private.

If present, a project-local `.env` supplies standalone container settings via
Docker's `--env-file`. Set `SAML_IDP_BASE_URL` to the public URL when using a
different port or a reverse proxy; `just container-run 8080` exposes loopback
port 8080. Override `IDP_ENV_FILE` to select another environment file and
`IDP_IMAGE` to select another image tag. Shared Compose settings remain in
`examples/.env` and `examples/docker-compose.yml`.

For outgoing email, set `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, and
`DEFAULT_FROM_EMAIL` in the standalone container's `.env`. SMTP defaults to
`smtp.gmail.com`, port `587`, and STARTTLS; override these with `EMAIL_HOST`,
`EMAIL_PORT`, and `EMAIL_USE_TLS`. For Gmail, use an app password without spaces.
For implicit TLS, use port `465`, `EMAIL_USE_TLS=false`, and `EMAIL_USE_SSL=true`.
The SMTP connection timeout is 15 seconds, configurable with `EMAIL_TIMEOUT`.
Keep credentials out of Git, and
rebuild and recreate the container after changing settings code; recreate it
after changing environment variables. For the shared Compose stack, put these
variables in `examples/.env`; Compose forwards them to the IdP container.

Without an explicit SMTP host or credentials, Django's console mailer prints
reset emails and their links to stdout/container logs. Set
`EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend` to explicitly
select this mode for testing. Configured SMTP failures are logged and never
fall back to printing reset links.

For local Python development:

```console
just setup
just migrate
just keygen
just create-user admin admin@example.org --admin
just collectstatic
just run
```

Frequently used local commands:

| Command | Purpose |
| --- | --- |
| `just create-user USERNAME EMAIL [--admin]` | Create an account and print a generated password |
| `just set-password USERNAME` | Generate and print a replacement password |
| `just set-password USERNAME --password-stdin` | Read an explicit password from stdin |
| `just set-admin USERNAME enable` / `disable` | Grant or revoke administration |
| `just import-users FILE` | Atomically import legacy JSON profiles |
| `just seed-demo` | Explicitly create lesson accounts |
| `just verify` | System checks, migration drift check, and tests |
| `just test-integration` | Real signed SSO/SLO exchanges with the sibling SP through Django test clients |
| `just manage COMMAND ...` | Run any other Django management command |
| `just shell` | Open the local Django shell |
| `just add-sp FILE` | Copy trusted SP metadata; restart the IdP to reload |
| `just metadata [BASE_URL]` | Fetch metadata from a running IdP |

## Run the shared stack

Compose, Caddy, `.env-example`, and the active `justfile` live in
[`examples/`](../). Follow [the shared setup](../README.md) for hostnames, mkcert,
TLS, building the local wheel, and exchanging IdP/SP metadata.

There are **no default accounts or shared passwords**. The IdP uses a fresh
SQLite database at `data/db.sqlite3`. It never deletes an existing database.

From `examples/`, build the images and create an administrator before starting
the HTTP services:

```console
cp .env-example .env
just wheel tls swamid-cert build
docker compose run --rm idp python manage.py idp_user create admin --email admin@example.org --admin
just up
just link
```

The one-off container runs key generation, migrations, and static collection
through its entrypoint, then runs the requested command. Direct account commands
need a migrated database but do not read SAML signing keys or certificates.
Users and sessions persist in the `django-idp/data` bind mount across restarts.
The session lifetime defaults to one hour.

## Profile and password changes

Sign in at `/idp/login/` to open **Your profile** at `/idp/profile/`. SAML login
still continues to the requesting SP. You can also open your profile through
your username in the header or the **Your profile and password** link on the
IdP home page.

The profile shows your username, name, and email as read-only details. To change
your password, enter your current password and the new password twice. The same
15–128 character and common-password rules used by the CLI apply; the browser
form has no weak-password override. The form requires login and CSRF protection,
and its responses are not cached.

A successful change rotates and preserves the current browser's IdP session,
including its SAML logout associations. Other IdP browser sessions are invalidated
when they next authenticate a request. Existing SP sessions are managed separately
through Single Logout. Only the current user's password can be changed here;
operators can still replace another account's password using the commands below.
If logout invalidates the session, or the session expires while the new password
is being hashed, the change is rejected with HTTP 409. Sign in again before
retrying; the password is not changed and the ended login is not restored.

## IdP administration

The navigation's retro Home button loads directly from
[GIFCities](https://blob.gifcities.org/gifcities/WFK6P4IAS6OXPXZX3TFLYNIAFMGWVF6G.gif).

Open `/idp-admin/` on your IdP hostname (for example,
`http://localhost:8000/idp-admin/` for the standalone container). Sign in with an
active account whose administrator flag is enabled. Signed-in administrators
also have an **IdP admin** link in the header. Ordinary accounts receive a 403.
The built-in Django `/admin/` remains disabled.

The interface provides searchable, paginated accounts, creation and editing,
comma-separated group membership, activation and administrator status, password
replacement, and confirmed deletion. Groups never grant administrative access.
Group membership uses a single CSV row; quote names containing commas, quotes,
or newlines (for example, `Students, "cn=staff,ou=groups"`). Existing names are
serialized with quoting so unrelated profile edits preserve them unchanged.
The final active administrator cannot be disabled, demoted, or deleted.

Creation and password replacement display a random 24-character password only
in the result response; copy it before leaving. Plaintext passwords are never
stored in sessions or messages. Password replacement invalidates previous IdP
sessions on their next request. Deleting an account permanently removes its
identity; recreating the username creates a new identity. Administrator email
setup/resend actions and database-backed SP administration remain pending.

Bootstrap or promote an administrator using the commands below, then rebuild
and recreate the container to serve updated application code.

## Forgot password

The login page links to `/idp/password-reset/`. Enter the account email address;
active accounts with a usable password receive a reset link by email (or in
logs when SMTP is not configured). The confirmation is identical for eligible,
unknown, disabled, blocked, and email-limited accounts. Reset links use `SAML_IDP_BASE_URL`,
never the request Host header, and expire after one hour. Opening a link does
not change the password. Successful completion invalidates the link and all
previous IdP sessions on their next request, and requires signing in again.

Permitted requests enqueue only the normalized address; account eligibility,
blocklist checks, token creation, and SMTP/console delivery run in a background
worker. HTTP responses never wait on SMTP, including for unknown or blocked
addresses. The worker releases SQLite's write lock before delivery and rechecks
the blocklist immediately before sending. Accounts created after a request was
queued do not receive a reset from that earlier request.

The normal container entrypoint supervises Gunicorn and the delivery worker
together, forwarding shutdown and stopping the service if either process exits.
For local development, run `just recovery-worker` in a second terminal alongside
`just run`. Use `just recovery-worker --once` to drain currently available jobs
and exit. Equivalently, use `python manage.py idp_recovery_worker [--once]`.
Queued addresses are deleted after processing, and jobs older than one hour are
discarded. A crashed worker's claim becomes available again after its lease
(at least five minutes, extended for longer configured SMTP timeouts). SMTP
failures are logged without automatic retries or console fallback.

Administrators can manage a persistent address blocklist at
`/idp-admin/blocked-emails/`, linked from the account list. Add addresses one per
line or separated by commas; matching uses the same case-insensitive Unicode
normalization as account email addresses, and duplicates are ignored. The entire
submission is validated before any addresses are added. Addresses can be blocked
before an account exists, and remain blocked after account deletion or recreation.

Blocked addresses receive no reset emails or console reset links. Existing reset
links also cannot be used while the address is blocked. Unblocking allows future
recovery requests again; it does not send an email. Normal login, current-password
changes, and manual administrative password replacement still work. Account
creation continues to display a generated password without sending email.

Recovery quotas are stored in SQLite and shared across workers and restarts:

| Setting | Default quota |
| --- | --- |
| `SAML_IDP_RESET_IP_LIMIT` | 10 reset requests per source IP per 15 minutes |
| `SAML_IDP_RESET_EMAIL_LIMIT` | 5 reset requests per normalized email address per hour |
| `SAML_IDP_RESET_CONFIRM_LIMIT` | 20 reset completion attempts per source IP per 15 minutes |

Email-limited requests still show the generic confirmation; IP-limited requests
return HTTP 429 with `Retry-After`. Counts include unknown addresses and invalid
submissions. Expired quotas are removed on subsequent recovery requests. Only
HMAC keys, counts, and expiry times are stored in the quota table.

By default, source IP means the direct connection's `REMOTE_ADDR`. Behind Caddy,
set `SAML_IDP_TRUSTED_PROXIES` to the proxy's actual IP or dedicated subnet
(comma separated) to use its `X-Forwarded-For` client addresses. Without this,
clients behind the proxy share an IP quota. Forwarding headers from untrusted
peers are ignored; do not trust arbitrary networks.

Rebuild and recreate the container to apply this feature. The entrypoint runs
the new quota-table migration automatically. For local development, run
`just migrate` before starting the server. For console delivery, view links with
`just logs idp` (Compose) or `docker logs django-idp` (standalone).

## Account commands

Run these inside `django-idp/` for local development, or prefix them with
`docker compose run --rm idp` from `examples/`:

```console
python manage.py migrate
python manage.py idp_user create alice --email alice@example.org
python manage.py idp_user create operator --email operator@example.org --admin
python manage.py idp_user set-password alice
python manage.py idp_user set-admin alice --enable
python manage.py idp_user set-admin alice --disable
```

Creation and password replacement generate independent random 24-character
passwords and print them once, after a successful commit. Only Django password
hashes are stored. Keep command output private. Creation does not force a
password change on first login. Password replacement invalidates existing browser
sessions when they next authenticate a request.

To supply a password, use `--password-stdin` on `create` or `set-password`.
The command reads one line, removes its line terminator, and preserves spaces.
Use an interactive hidden prompt rather than putting credentials in shell history:

```bash
read -rs -p 'Password: ' idp_password
printf '\n'
printf '%s\n' "$idp_password" | python manage.py idp_user set-password alice --password-stdin
unset idp_password
```

The default policy accepts 15–128 characters, including spaces, and rejects
Django's common-password list. There are no character-class rules. An explicit
`--allow-weak-password` together with `--password-stdin` permits short passwords
for lessons; empty passwords and values longer than 128 characters are rejected.
Explicit passwords are never echoed by these commands.

Username and email are NFKC-normalized, trimmed, and case-folded. Each must be
unique, including across accounts' username/email fields so login cannot be
ambiguous. Email is required. Every account has an immutable random UUID.
`is_staff` controls IdP administration separately from SAML groups. The last
active administrator cannot be demoted, disabled, or deleted through the account
mutation API; SQLite IMMEDIATE transactions serialize competing changes.

## Import legacy JSON accounts

Import is explicit; startup does not read JSON. The importer accepts the Go
example's array format or an object containing a `users` array:

```json
[
  {
    "name": "alice",
    "email": "alice@example.org",
    "given_name": "Alice",
    "surname": "Andersson",
    "common_name": "Alice Example",
    "groups": ["Students"],
    "scoped_affiliation": "student@example.org"
  }
]
```

```console
python manage.py idp_import_users /path/to/users.json
```

For Compose, mount the JSON read-only into a one-off container:

```console
docker compose run --rm -v /absolute/path/users.json:/import/users.json:ro idp python manage.py idp_import_users /import/users.json
```

Supported aliases are `username`/`name`, `email`/`mail`,
`display_name`/`common_name`/`displayName`/`cn`,
`given_name`/`givenName`/`first_name`, `surname`/`family_name`/`last_name`/`sn`,
and `scoped_affiliation`/`eduPersonScopedAffiliation`. Conflicting aliases are
rejected. Groups must be an array of nonempty names.

Old password/hash fields and admin flags are ignored. All imported accounts
receive fresh random passwords, printed once after the entire import commits.
A group named `Administrators` grants no administration rights; promote a chosen
account explicitly with `idp_user set-admin USERNAME --enable`.

All records are validated before writing. Any invalid record, duplicate,
ambiguous identifier, or existing-account conflict rejects the whole import,
without partial accounts or groups. Re-importing existing users is an error,
not an update. Imported users can request a reset link from the login page;
automatic setup-link email delivery remains pending.

`python manage.py seed_demo` remains an optional lesson command. It creates eight
sample users with individual random passwords, prints new credentials once,
and skips existing usernames. It creates no administrator. To deliberately use
a shared teaching password, pass `--password-stdin --allow-weak-password`.

## SAML Single Logout

The IdP publishes **`/idp/slo/`** in metadata for HTTP-Redirect and HTTP-POST
requests and responses. It supports SP-initiated and IdP-initiated browser logout,
including propagation to the other SPs participating in the affected IdP session.
The sibling SP publishes `/sp/slo/` with the same bindings.

Use **Log out of connected services** on either application's page. Local actions
at `/idp/logout/` and `/sp/logout/` now require a CSRF-protected **POST**. Existing
GET logout links must be changed to forms. Local sessions end before the browser
continues through the remote providers, even if a provider later fails.

Each successful SSO records the exact issued NameID (value, format and all
qualifiers), SessionIndex, browser session key, and expiry in SQLite. Cleanup
uses the persisted browser session's expiry, so a later SSO renewal retains
earlier SP associations. An incoming
SP request can invalidate only its own matching subject/session associations.
With SessionIndex, logout targets those sessions; without indexes, it targets
all sessions matching that SP and full NameID. IdP-initiated logout targets the
current browser's IdP session and its participating SP sessions. Other independent
browser sessions are retained unless a matching index-free SP request covers them.
Every supplied SessionIndex must match that SP and full NameID. Mixing known and
unknown indexes rejects the whole request without ending the matching sessions.
Propagation skips only the associations covered by the initiating LogoutRequest;
other associations at that same SP are also contacted. The sibling SP remembers
superseded associations as already ended, so repeated SSO with new transient
NameIDs can still complete logout successfully without affecting a newer subject.

Logout requests and responses must be signed with a key in the issuer's trusted
metadata. Redirect signatures cover the exact encoded query; POST messages carry
an enveloped XML signature covering the protocol element. Rollover signing keys
are supported. Destinations, issuer, timestamps, full subject/session association,
and response correlation are checked before the corresponding action is accepted.
Replay reservations and pending flows are database-backed and shared by workers.
Response correlation requires both the signed `InResponseTo` and an opaque random
RelayState, and does not depend on a browser cookie being sent on cross-site POST.

Metadata resolution happens outside database write transactions. Before ending
sessions, logout rechecks the complete participant set and its current browser
keys inside the invalidation transaction. If a concurrent password change rotates
a key or SSO adds an association, preparation retries with the refreshed state.
SSO also records its session renewal and new association in one transaction.
Preparation makes at most three attempts; continuous changes return an error to the
initiating SP, or HTTP 409 with a retry message for local logout, rather than
claiming successful logout from an outdated snapshot.

Flows expire after five minutes, with a 60-second clock allowance for incoming
message timestamps. Missing endpoints and negative/partial responses are reported
as partial logout. If the browser gets stuck at an unreachable SP, return to
**`/idp/logout/status/`** in the same browser to skip it and continue; skipping
always records partial logout. After flow expiry, that page reports incomplete
logout. A provider that never responds may retain its own session. SOAP, Artifact
logout and encrypted NameIDs are not implemented.
Recovery POSTs check the flow and its expiry under the write lock. A stale,
expired, or already-completed request returns HTTP 400, including when a valid
LogoutResponse or another recovery request completes the flow concurrently.

Recovery uses a separate, signed HttpOnly cookie limited to `/idp/logout/`, with
a five-minute lifetime and SameSite=Lax. It is Secure when the configured public
IdP URL uses HTTPS. Cookie-less SAML POSTs do not create an anonymous authentication
session or overwrite the browser's existing IdP authentication cookie.

After upgrading both applications:

```console
# From examples/: entrypoints migrate both databases without deleting data.
just up
just link
```

`just link` refreshes both metadata files and restarts the services to reload
their caches. For other SPs, redistribute the IdP metadata and import their
updated metadata containing SingleLogoutService and signing certificates.
Sign in again to establish tracked sessions; sessions issued before this feature
have no SAML logout associations. For local Python execution, run `just migrate`
here and `python manage.py migrate` in `django-sp/`.

The protocol follows the browser Single Logout profile described by
[OASIS](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html).

## Current SAML behavior

- `/idp/metadata` publishes the signing certificate, both SSO bindings, and an
  error URL. `/idp/sso/` validates requests against registered metadata and
  signs assertions before returning the SAML response.
- SP resolution currently uses local XML files in `SAML_IDP_METADATA_DIR`, then
  signature-verified MDQ through `SAML_IDP_MDQ_URL` and
  `SAML_IDP_METADATA_CERT`. Local metadata is trusted as supplied. Restart to
  reload local files. Database imports will replace this in a later step.
- Released attributes include `displayName`, `uid`, `givenName`, `sn`, `mail`,
  multivalued `memberOf`, and configured scoped affiliation. Setting
  `SAML_IDP_SCOPE` also enables principal-name and affiliation fallbacks.
  Display name falls back to full name then username; scoped affiliation falls
  back to `member@<scope>`. Admin status is never released as a group.
- NameIDs currently retain the previous transient/persistent/email behavior;
  the planned UUID-based persistent mapping and email-format rejection are pending.

## Local development and checks

Python 3.12 or later is required. Build a wheel from the repository root with
`maturin build` and install it alongside this example's dependencies:

```console
uv venv
uv pip install --find-links ../../target/wheels -r pyproject.toml
export DJANGO_DEBUG=1 SAML_IDP_BASE_URL=http://localhost:8000
.venv/bin/python manage.py migrate
.venv/bin/python manage.py idp_user create admin --email admin@example.org --admin
.venv/bin/python manage.py idp_keys
.venv/bin/python manage.py collectstatic --noinput
.venv/bin/python manage.py runserver
```

```console
.venv/bin/python manage.py check
.venv/bin/python manage.py makemigrations --check --dry-run
.venv/bin/python manage.py test idp.tests --settings=config.test_settings --noinput
```

Test settings use a temporary file-backed SQLite database so separate writer
connections exercise the IMMEDIATE transaction safeguard, and a fast test-only
password hasher. Production settings use Django's default password hashers.
With no SP metadata source, system checks emit a configuration warning; this
does not prevent account bootstrap.

Runtime configuration remains in `config/settings.py` and the shared Compose
file. Known development secrets, pending login throttling, and the
remaining session/SAML hardening in the plan must be addressed before using
this example with real accounts outside a local teaching environment.
