from django.apps import AppConfig


class SamlSpConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "sp"
    verbose_name = "SAML Service Provider"

    def ready(self):
        from . import checks  # noqa: F401  (registers system checks)
