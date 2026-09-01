# A self-contained SAML SP image on Debian trixie.
# Build context is this directory (examples/django-sp).
#
# NOTE on worker count: this example keeps replay detection and persistent-NameID
# uniqueness in per-process, in-memory stores (_replay_cache / _persistent_id_store).
# Those protections are only consistent within a single process, so the image runs
# a single gunicorn worker. Scaling to multiple workers (or replicas) requires
# moving both stores to a shared backend first, otherwise a replay can succeed by
# landing on a worker that has not yet seen the assertion.
FROM debian:trixie-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    DJANGO_SETTINGS_MODULE=config.settings \
    PATH="/app/.venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# uv: fast, reproducible Python dependency installation.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# `just up` stages the repository's local pygamlastan wheel in ./wheels before
# this image is built.
COPY . /app
RUN mkdir -p /app/wheels

# Install dependencies from the staged wheel without assuming 0.4.0 is on PyPI.
RUN uv venv /app/.venv \
 && uv pip install --find-links /app/wheels \
        "django==6.0.7" "pygamlastan>=0.4.0" "cryptography>=50" "gunicorn>=26" "whitenoise>=6.12"

RUN chmod +x /app/entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "1", "--timeout", "60"]
