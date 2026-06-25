#!/bin/sh
# Prepare the IdP on every start: keys, schema, static files, demo accounts.
set -e

# Generate the signing key + self-signed cert if the data volume has none.
python manage.py idp_keys

python manage.py migrate --noinput
python manage.py collectstatic --noinput
python manage.py seed_demo

# If MDQ is configured, its signing cert must be present for verification. When
# bringing the stack up with plain `docker compose up` (instead of `just up`),
# the cert may not have been fetched yet - warn rather than fail silently.
if [ -n "$SAML_IDP_MDQ_URL" ] && [ -n "$SAML_IDP_METADATA_CERT" ] && [ ! -f "$SAML_IDP_METADATA_CERT" ]; then
    echo "WARNING: SAML_IDP_METADATA_CERT=$SAML_IDP_METADATA_CERT not found."
    echo "         MDQ-based SP resolution will be rejected until it exists."
    echo "         On the host run:  just swamid-cert   (writes ./data/swamid-signing.pem)"
fi

exec "$@"
