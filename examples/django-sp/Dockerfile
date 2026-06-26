# A self-contained SAML SP image on Debian trixie.
# Build context is this directory (examples/django-sp).
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

# Copy the app (including optional ./wheels) so the build works whether or not a local wheel is present.
COPY . /app
RUN mkdir -p /app/wheels

# Install dependencies. If a local pygamlastan wheel is present in ./wheels it will win via --find-links.
RUN uv venv /app/.venv \
 && uv pip install --find-links /app/wheels \
        "django==6.0.6" "pygamlastan>=0.1" "cryptography>=42" "gunicorn>=22" "whitenoise>=6"

RUN chmod +x /app/entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "60"]
