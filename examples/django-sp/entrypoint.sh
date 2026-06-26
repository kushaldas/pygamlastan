#!/bin/sh
# Prepare the SP on every start: keys, schema, static files.
set -e

# Generate the SP key + self-signed cert if the data volume has none.
python manage.py sp_keys

python manage.py migrate --noinput
python manage.py collectstatic --noinput

# If MDQ is configured, its signing cert must be present for verification.
if [ -n "$SAML_SP_MDQ_URL" ] && [ -n "$SAML_SP_METADATA_CERT" ] && [ ! -f "$SAML_SP_METADATA_CERT" ]; then
    echo "WARNING: SAML_SP_METADATA_CERT=$SAML_SP_METADATA_CERT not found."
    echo "         MDQ-based IdP resolution will be rejected until it exists."
fi

exec "$@"
