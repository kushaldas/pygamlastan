"""Load both self-contained example apps for signed SSO/SLO integration tests."""
import sys

from .test_settings import *  # noqa: F403

sys.path.append(str(BASE_DIR.parent / "django-sp"))  # noqa: F405
INSTALLED_APPS = [*INSTALLED_APPS, "sp"]  # noqa: F405
ROOT_URLCONF = "config.integration_test_urls"
SAML_SP_MDQ_URL = ""
SAML_SP_METADATA_CERT = ""
SAML_SP_IDP_ENTITYID = "https://idp.example.org/idp/metadata"
SAML_SP_DISCOVERY_URL = ""
SAML_SP_METADATA_DIR = str(BASE_DIR / "data" / "integration-unused-metadata")  # noqa: F405
