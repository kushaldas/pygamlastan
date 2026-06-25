"""Shared pytest fixtures for the pygamlastan test suite.

Provides an RSA key/cert pair (via openssl) for file-based signing tests, and a
provisioned SoftHSM2 token for the PKCS#11 path. PKCS#11 tests self-skip when
softhsm2-util / pkcs11-tool are not installed.
"""

import base64
import os
import shutil
import subprocess
import textwrap

import pytest

SOFTHSM_MODULE_CANDIDATES = [
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
]


def _have(cmd):
    return shutil.which(cmd) is not None


@pytest.fixture(scope="session")
def rsa_keypair(tmp_path_factory):
    """Return (private_key_pem: bytes, cert_pem: bytes, cert_der_b64: str)."""
    if not _have("openssl"):
        pytest.skip("openssl not available")
    d = tmp_path_factory.mktemp("keys")
    key = d / "key.pem"
    cert = d / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "3650",
         "-subj", "/CN=pygamlastan-test"],
        check=True, capture_output=True,
    )
    der = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    return key.read_bytes(), cert.read_bytes(), base64.b64encode(der).decode()


@pytest.fixture(scope="session")
def softhsm(tmp_path_factory):
    """Provision a SoftHSM2 token with an RSA key; return (module, pin, label).

    Skips the whole test if SoftHSM2 tooling is unavailable.
    """
    module = next((m for m in SOFTHSM_MODULE_CANDIDATES if os.path.exists(m)), None)
    if module is None or not _have("softhsm2-util") or not _have("pkcs11-tool"):
        pytest.skip("SoftHSM2 / pkcs11-tool not available")

    base = tmp_path_factory.mktemp("softhsm")
    tokens = base / "tokens"
    tokens.mkdir()
    conf = base / "softhsm2.conf"
    conf.write_text(textwrap.dedent(f"""\
        directories.tokendir = {tokens}
        objectstore.backend = file
        log.level = ERROR
    """))
    os.environ["SOFTHSM2_CONF"] = str(conf)

    pin, label = "1234", "saml-signing-key"
    subprocess.run(
        ["softhsm2-util", "--init-token", "--slot", "0", "--label", "saml",
         "--so-pin", "0000", "--pin", pin],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["pkcs11-tool", "--module", module, "--login", "--pin", pin,
         "--keypairgen", "--key-type", "rsa:2048", "--label", label],
        check=True, capture_output=True,
    )
    return module, pin, label
