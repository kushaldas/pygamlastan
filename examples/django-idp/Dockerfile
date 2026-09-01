# A self-contained SAML IdP image on Debian trixie.
# Build context is this directory (examples/django-idp).
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

# `just up` builds and stages the repository's local pygamlastan wheel before
# this image is built, so no unpublished release artifact is assumed.
COPY wheels/ /app/wheels/
RUN uv venv /app/.venv \
 && uv pip install --find-links /app/wheels \
        "django==6.0.7" "pygamlastan>=0.4.0" "cryptography>=50" "gunicorn>=26" "whitenoise>=6.12"

COPY . /app
RUN chmod +x /app/entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "60"]
