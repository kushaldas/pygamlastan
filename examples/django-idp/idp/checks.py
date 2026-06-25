"""Startup checks for SP metadata configuration.

- A signing cert is mandatory **when MDQ is used** (remote metadata is verified).
- Local metadata files are trusted as provided and need no cert.
- At least one SP source (local files or MDQ) should be configured.
"""
from pathlib import Path

from django.conf import settings
from django.core.checks import Error, Warning, register


@register()
def federation_config(app_configs, **kwargs):
    issues = []

    md_dir = Path(settings.SAML_IDP_METADATA_DIR)
    has_files = md_dir.is_dir() and any(md_dir.glob("*.xml"))

    if settings.SAML_IDP_MDQ_URL and not settings.SAML_IDP_METADATA_CERT:
        issues.append(
            Error(
                "SAML_IDP_METADATA_CERT must be set when SAML_IDP_MDQ_URL is used; "
                "MDQ metadata signature verification is mandatory.",
                hint="Fetch the federation signing cert: `just swamid-cert`.",
                id="idp.E001",
            )
        )

    if not settings.SAML_IDP_MDQ_URL and not has_files:
        issues.append(
            Warning(
                "No SP metadata source configured: set SAML_IDP_MDQ_URL, or place "
                "SP metadata XML files in SAML_IDP_METADATA_DIR.",
                hint="Set SAML_IDP_MDQ_URL in .env, or `just add-sp <file>`.",
                id="idp.W001",
            )
        )
    return issues
