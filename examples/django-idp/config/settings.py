"""Django settings for the pygamlastan SAML IdP example.

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
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "idp",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
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
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# --- Data / database -------------------------------------------------------

DATA_DIR = Path(os.environ.get("SAML_IDP_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(DATA_DIR / "db.sqlite3"),
        "OPTIONS": {"timeout": 20, "transaction_mode": "IMMEDIATE"},
    }
}

AUTH_USER_MODEL = "idp.User"
AUTHENTICATION_BACKENDS = ["idp.backends.IdentifierBackend"]
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "idp.passwords.PasswordLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
]
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_AGE = 3600

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# --- Outgoing email --------------------------------------------------------

_email_host = os.environ.get("EMAIL_HOST") or "smtp.gmail.com"
_email_port = int(os.environ.get("EMAIL_PORT", "587"))
_email_use_tls = _env_bool("EMAIL_USE_TLS", True)
_email_use_ssl = _env_bool("EMAIL_USE_SSL", False)
_email_host_user = os.environ.get("EMAIL_HOST_USER", "")
_email_host_password = os.environ.get("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL") or _email_host_user or "idp@localhost"
_email_timeout = int(os.environ.get("EMAIL_TIMEOUT", "15"))
# An explicit host also supports SMTP relays without username/password auth.
_smtp_configured = bool(os.environ.get("EMAIL_HOST") or _email_host_user or _email_host_password)
_email_backend = os.environ.get("EMAIL_BACKEND") or (
    "django.core.mail.backends.smtp.EmailBackend" if _smtp_configured
    else "django.core.mail.backends.console.EmailBackend"
)
MAILERS = {"default": {"BACKEND": _email_backend}}
if _email_backend == "django.core.mail.backends.smtp.EmailBackend":
    MAILERS["default"]["OPTIONS"] = {
        "host": _email_host, "port": _email_port, "username": _email_host_user,
        "password": _email_host_password, "use_tls": _email_use_tls,
        "use_ssl": _email_use_ssl, "timeout": _email_timeout,
    }

PASSWORD_RESET_TIMEOUT = 3600
SAML_IDP_RESET_IP_LIMIT = int(os.environ.get("SAML_IDP_RESET_IP_LIMIT", "10"))
SAML_IDP_RESET_EMAIL_LIMIT = int(os.environ.get("SAML_IDP_RESET_EMAIL_LIMIT", "5"))
SAML_IDP_RESET_CONFIRM_LIMIT = int(os.environ.get("SAML_IDP_RESET_CONFIRM_LIMIT", "20"))
# Only trust forwarding headers from explicitly configured proxy IPs/subnets.
SAML_IDP_TRUSTED_PROXIES = [
    value.strip() for value in os.environ.get("SAML_IDP_TRUSTED_PROXIES", "").split(",")
    if value.strip()
]

# --- Static files (served by WhiteNoise) -----------------------------------

STATIC_URL = "static/"
STATIC_ROOT = str(DATA_DIR / "static")
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "idp:login"

# --- Behind the Caddy reverse proxy (TLS terminated at the proxy) ----------

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True

CSRF_TRUSTED_ORIGINS = [
    o for o in os.environ.get("DJANGO_CSRF_TRUSTED", "https://localhost").split(",") if o
]

# --- SAML IdP configuration ------------------------------------------------

SAML_IDP_BASE_URL = os.environ.get("SAML_IDP_BASE_URL", "http://localhost:8000").rstrip("/")
SAML_IDP_ENTITY_ID = os.environ.get(
    "SAML_IDP_ENTITY_ID", f"{SAML_IDP_BASE_URL}/idp/metadata"
)
SAML_IDP_KEY = os.environ.get("SAML_IDP_KEY", str(DATA_DIR / "idp_key.pem"))
SAML_IDP_CERT = os.environ.get("SAML_IDP_CERT", str(DATA_DIR / "idp_cert.pem"))
# Secret used to derive opaque, per-SP persistent NameIDs (eduPersonTargetedID).
SAML_IDP_NAMEID_SECRET = os.environ.get(
    "SAML_IDP_NAMEID_SECRET", "demo-persistent-id-secret-change-me"
)
# Support contact shown on the error page (the metadata errorURL target).
SAML_IDP_SUPPORT_EMAIL = os.environ.get("SAML_IDP_SUPPORT_EMAIL", "")
# Home-organization scope for scoped attributes (eduPersonPrincipalName,
# eduPersonScopedAffiliation): the "@<scope>" suffix, e.g. "gamlastan.sverige".
SAML_IDP_SCOPE = os.environ.get("SAML_IDP_SCOPE", "")

# --- Federation SP metadata (resolved at request time; no local SP database) ---
# Two sources, tried local-first:
#   1. local metadata XML files in SAML_IDP_METADATA_DIR (trusted as provided)
#   2. an MDQ service in SAML_IDP_MDQ_URL (queried on demand, signature-verified
#      against SAML_IDP_METADATA_CERT - mandatory whenever MDQ is set)
SAML_IDP_METADATA_DIR = os.environ.get("SAML_IDP_METADATA_DIR", str(DATA_DIR / "metadata"))
SAML_IDP_MDQ_URL = os.environ.get("SAML_IDP_MDQ_URL", "")
# PEM cert used to signature-verify MDQ metadata before trust.
SAML_IDP_METADATA_CERT = os.environ.get("SAML_IDP_METADATA_CERT", "")
