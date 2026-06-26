"""Startup checks for IdP metadata configuration.

- A signing cert is mandatory **when MDQ is used** (remote metadata is verified).
- Local metadata files are trusted as provided and need no cert.
- An IdP entityID and at least one metadata source should be configured.
"""
from pathlib import Path

from django.conf import settings
from django.core.checks import Error, Warning, register


@register()
def federation_config(app_configs, **kwargs):
    issues = []

    md_dir = Path(settings.SAML_SP_METADATA_DIR)
    has_files = md_dir.is_dir() and any(md_dir.glob("*.xml"))

    if settings.SAML_SP_MDQ_URL and not settings.SAML_SP_METADATA_CERT:
        issues.append(
            Error(
                "SAML_SP_METADATA_CERT must be set when SAML_SP_MDQ_URL is used; "
                "MDQ metadata signature verification is mandatory.",
                hint="Fetch the federation signing cert: `just swamid-cert`.",
                id="sp.E001",
            )
        )

    if not settings.SAML_SP_MDQ_URL and not has_files:
        issues.append(
            Warning(
                "No IdP metadata source configured: set SAML_SP_MDQ_URL, or place "
                "IdP metadata XML files in SAML_SP_METADATA_DIR.",
                hint="Set SAML_SP_MDQ_URL in .env, or `just add-idp <file>`.",
                id="sp.W001",
            )
        )

    if not settings.SAML_SP_IDP_ENTITYID and not settings.SAML_SP_DISCOVERY_URL:
        issues.append(
            Warning(
                "Neither SAML_SP_IDP_ENTITYID nor SAML_SP_DISCOVERY_URL is set; the "
                "login flow has no IdP to send users to and no way to pick one.",
                hint="Set SAML_SP_DISCOVERY_URL (federation) or SAML_SP_IDP_ENTITYID "
                "(single IdP).",
                id="sp.W002",
            )
        )
    return issues
