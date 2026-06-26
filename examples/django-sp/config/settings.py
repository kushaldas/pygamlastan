"""Django settings for the pygamlastan SAML SP example.

Everything that varies between environments is driven by environment variables
so the same image runs locally and behind Caddy. Defaults are tuned for a quick
local demo - review the SECURITY section before any real use.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(int(default))).lower() in ("1", "true", "yes", "on")


# --- Core ------------------------------------------------------------------

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-insecure-change-me")
DEBUG = _env_bool("DJANGO_DEBUG", False)
ALLOWED_HOSTS = [h for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",") if h]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "sp.apps.SamlSpConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# --- Data / database -------------------------------------------------------
# The SP stores nothing about users in a DB; SQLite holds only sessions (the
# SAML identity is kept in the session after a successful login).

DATA_DIR = Path(os.environ.get("SAML_SP_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(DATA_DIR / "db.sqlite3"),
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# --- Static files (served by WhiteNoise) -----------------------------------

STATIC_URL = "static/"
STATIC_ROOT = str(DATA_DIR / "static")
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- Behind the Caddy reverse proxy (TLS terminated at the proxy) ----------

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True

CSRF_TRUSTED_ORIGINS = [
    o for o in os.environ.get("DJANGO_CSRF_TRUSTED", "https://localhost").split(",") if o
]

# The IdP delivers the Response as a cross-site top-level POST to the ACS. With
# the default SameSite=Lax the session cookie (holding the pending request id)
# would not be sent on that POST, breaking the InResponseTo binding. SameSite=None
# (which requires Secure) lets the cookie ride along. We always run behind TLS.
SESSION_COOKIE_SAMESITE = os.environ.get("DJANGO_SESSION_SAMESITE", "None")
SESSION_COOKIE_SECURE = _env_bool("DJANGO_SESSION_COOKIE_SECURE", True)

# --- SAML SP configuration -------------------------------------------------

SAML_SP_BASE_URL = os.environ.get("SAML_SP_BASE_URL", "http://localhost:8000").rstrip("/")
SAML_SP_ENTITY_ID = os.environ.get(
    "SAML_SP_ENTITY_ID", f"{SAML_SP_BASE_URL}/sp/metadata"
)
SAML_SP_KEY = os.environ.get("SAML_SP_KEY", str(DATA_DIR / "sp_key.pem"))
SAML_SP_CERT = os.environ.get("SAML_SP_CERT", str(DATA_DIR / "sp_cert.pem"))

# Optional fixed IdP: if set, login goes straight to this IdP and discovery is
# skipped. Leave empty to send users to the discovery service (the federation
# case) so they can pick any IdP. Its metadata is resolved (local file or MDQ)
# to find the SSO endpoint and the signing cert used to verify the Response.
SAML_SP_IDP_ENTITYID = os.environ.get("SAML_SP_IDP_ENTITYID", "")

# SAML IdP Discovery Service (SeamlessAccess). When no fixed IdP is set, login
# redirects here with the SAMLDS entityID + return params; the DS sends the user
# back to the ACS-side discovery endpoint with the chosen IdP's entityID.
SAML_SP_DISCOVERY_URL = os.environ.get(
    "SAML_SP_DISCOVERY_URL", "https://ds.qa.swamid.se/ds/"
)

# --- IdP metadata resolution (no local IdP database) -----------------------
# Two sources, tried local-first:
#   1. local metadata XML files in SAML_SP_METADATA_DIR (trusted as provided)
#   2. an MDQ service in SAML_SP_MDQ_URL (queried on demand, signature-verified
#      against SAML_SP_METADATA_CERT - mandatory whenever MDQ is set)
SAML_SP_METADATA_DIR = os.environ.get("SAML_SP_METADATA_DIR", str(DATA_DIR / "metadata"))
SAML_SP_MDQ_URL = os.environ.get("SAML_SP_MDQ_URL", "")
SAML_SP_METADATA_CERT = os.environ.get("SAML_SP_METADATA_CERT", "")

# --- Metadata descriptive fields (shown to users / required by SWAMID) -----
SAML_SP_DISPLAY_NAME = os.environ.get("SAML_SP_DISPLAY_NAME", "pygamlastan demo SP")
SAML_SP_DESCRIPTION = os.environ.get(
    "SAML_SP_DESCRIPTION", "A pygamlastan example Service Provider that displays released attributes."
)
SAML_SP_INFO_URL = os.environ.get("SAML_SP_INFO_URL", f"{SAML_SP_BASE_URL}/")
# No privacy-statement page ships with this example, so default to empty; the
# metadata omits PrivacyStatementURL unless you set a real URL here.
SAML_SP_PRIVACY_URL = os.environ.get("SAML_SP_PRIVACY_URL", "")
SAML_SP_ORG_NAME = os.environ.get("SAML_SP_ORG_NAME", "pygamlastan")
SAML_SP_ORG_DISPLAY_NAME = os.environ.get("SAML_SP_ORG_DISPLAY_NAME", "pygamlastan demo")
SAML_SP_ORG_URL = os.environ.get("SAML_SP_ORG_URL", "https://github.com/kushaldas/pygamlastan")
# SWAMID requires technical, support, and (REFEDS) security contacts.
SAML_SP_TECHNICAL_EMAIL = os.environ.get("SAML_SP_TECHNICAL_EMAIL", "")
SAML_SP_SUPPORT_EMAIL = os.environ.get("SAML_SP_SUPPORT_EMAIL", "")
SAML_SP_SECURITY_EMAIL = os.environ.get("SAML_SP_SECURITY_EMAIL", "")
