"""Loads the IdP's identity, signing key/cert, and derived endpoint URLs once."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from django.conf import settings


@dataclass(frozen=True)
class IdpConfig:
    entity_id: str
    base_url: str
    sso_url: str
    metadata_url: str
    error_url: str  # SWAMID Tech 5.1.13: IdPs MUST advertise a registered errorURL
    key_pem: bytes
    cert_pem: bytes
    cert_b64: str  # single-line base64 DER, for <ds:X509Certificate>
    nameid_secret: str
    support_email: str
    scope: str  # home-org scope for scoped attributes (eppn, scopedAffiliation)


def _cert_b64_der(cert_pem: bytes) -> str:
    """The base64 DER body of a PEM certificate, as one line (PEM minus armor)."""
    body, inside = [], False
    for line in cert_pem.decode().splitlines():
        if "BEGIN CERTIFICATE" in line:
            inside = True
            continue
        if "END CERTIFICATE" in line:
            break
        if inside:
            body.append(line.strip())
    return "".join(body)


@lru_cache(maxsize=1)
def get_idp_config() -> IdpConfig:
    key_pem = Path(settings.SAML_IDP_KEY).read_bytes()
    cert_pem = Path(settings.SAML_IDP_CERT).read_bytes()
    base = settings.SAML_IDP_BASE_URL.rstrip("/")
    return IdpConfig(
        entity_id=settings.SAML_IDP_ENTITY_ID,
        base_url=base,
        sso_url=f"{base}/idp/sso/",
        metadata_url=f"{base}/idp/metadata",
        error_url=f"{base}/idp/error",
        key_pem=key_pem,
        cert_pem=cert_pem,
        cert_b64=_cert_b64_der(cert_pem),
        nameid_secret=settings.SAML_IDP_NAMEID_SECRET,
        support_email=settings.SAML_IDP_SUPPORT_EMAIL,
        scope=settings.SAML_IDP_SCOPE,
    )
