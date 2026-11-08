# A self-contained SAML IdP image on Debian trixie.
# Build context is this directory (examples/django-idp).
FROM debian:trixie-slim

LABEL org.opencontainers.image.title="Django SAML IdP" \
      org.opencontainers.image.version="0.2.0"

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

# `just build` builds and stages the repository's local pygamlastan wheel before
# this image is built, so no unpublished release artifact is assumed.
COPY wheels/ /app/wheels/
COPY pyproject.toml /app/pyproject.toml
RUN uv venv /app/.venv \
 && uv pip install /app/wheels/pygamlastan-*.whl -r /app/pyproject.toml

COPY . /app
RUN chmod +x /app/entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "60"]
