from django.apps import AppConfig


class SamlIdpConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "idp"
    verbose_name = "SAML Identity Provider"

    def ready(self):
        from . import checks  # noqa: F401  (registers system checks)
