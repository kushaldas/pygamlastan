"""Loads the SP's identity, key/cert, derived endpoint URLs, and the descriptive
metadata fields (display name, organization, contacts) once."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from django.conf import settings


@dataclass(frozen=True)
class SpConfig:
    entity_id: str
    base_url: str
    acs_url: str
    metadata_url: str
    login_url: str
    disco_return_url: str  # the <idpdisc:DiscoveryResponse> endpoint
    key_pem: bytes
    cert_pem: bytes
    cert_b64: str  # single-line base64 DER, for <ds:X509Certificate>
    idp_entity_id: str  # optional fixed IdP; empty -> use discovery
    discovery_url: str
    # Descriptive metadata (mdui / Organization / ContactPerson).
    display_name: str
    description: str
    info_url: str
    privacy_url: str
    org_name: str
    org_display_name: str
    org_url: str
    technical_email: str
    support_email: str
    security_email: str


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
def get_sp_config() -> SpConfig:
    key_pem = Path(settings.SAML_SP_KEY).read_bytes()
    cert_pem = Path(settings.SAML_SP_CERT).read_bytes()
    base = settings.SAML_SP_BASE_URL.rstrip("/")
    return SpConfig(
        entity_id=settings.SAML_SP_ENTITY_ID,
        base_url=base,
        acs_url=f"{base}/sp/acs/",
        metadata_url=f"{base}/sp/metadata",
        login_url=f"{base}/sp/login/",
        disco_return_url=f"{base}/sp/disco/",
        key_pem=key_pem,
        cert_pem=cert_pem,
        cert_b64=_cert_b64_der(cert_pem),
        idp_entity_id=settings.SAML_SP_IDP_ENTITYID,
        discovery_url=settings.SAML_SP_DISCOVERY_URL,
        display_name=settings.SAML_SP_DISPLAY_NAME,
        description=settings.SAML_SP_DESCRIPTION,
        info_url=settings.SAML_SP_INFO_URL,
        privacy_url=settings.SAML_SP_PRIVACY_URL,
        org_name=settings.SAML_SP_ORG_NAME,
        org_display_name=settings.SAML_SP_ORG_DISPLAY_NAME,
        org_url=settings.SAML_SP_ORG_URL,
        technical_email=settings.SAML_SP_TECHNICAL_EMAIL,
        support_email=settings.SAML_SP_SUPPORT_EMAIL,
        security_email=settings.SAML_SP_SECURITY_EMAIL,
    )
