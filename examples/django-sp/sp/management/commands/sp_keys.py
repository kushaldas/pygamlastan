"""Generate the SP signing/encryption key + self-signed certificate if missing."""
import datetime
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Generate the SP key and self-signed certificate if missing."

    def add_arguments(self, parser):
        parser.add_argument(
            "--force", action="store_true", help="Overwrite an existing key/cert."
        )

    def handle(self, *args, **options):
        key_path = Path(settings.SAML_SP_KEY)
        cert_path = Path(settings.SAML_SP_CERT)
        if key_path.exists() and cert_path.exists() and not options["force"]:
            self.stdout.write(
                f"SP key/cert already present at {key_path} (use --force to regenerate)."
            )
            return

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        common_name = settings.SAML_SP_ENTITY_ID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1825))
            .sign(key, hashes.SHA256())
        )
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.stdout.write(self.style.SUCCESS(f"Wrote {key_path} and {cert_path}"))
