"""``saml2.metadata`` shim: ``entity_descriptor(config)`` builds the SP's own
SAML metadata document from an :class:`~pygamlastan.compat.saml2.config.SPConfig`.

pygamlastan does not (yet) ship an SP-metadata *builder*, so this templates a
minimal, schema-valid ``<md:EntityDescriptor>`` from the configured entityid,
ACS/SLO endpoints and signing certificate - the same approach the pygamlastan
``django-sp`` example uses. The returned object exposes ``.to_string()`` /
``.to_xml()`` so the eduID metadata view keeps working.
"""

from __future__ import annotations

from xml.sax.saxutils import escape, quoteattr

from .config import SPConfig

_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS = "http://www.w3.org/2000/09/xmldsig#"


def _read_cert_body(cert_file: str | None) -> str | None:
    """Return the base64 DER body of a PEM certificate (no header/footer/ws).

    If ``cert_file`` is configured but cannot be read, raise rather than silently
    omitting the certificate from the generated metadata, so a misconfiguration
    fails fast instead of producing metadata without a signing key.
    """
    if not cert_file:
        return None
    try:
        with open(cert_file, encoding="ascii") as fh:
            pem = fh.read()
    except OSError as e:
        raise ValueError(f"configured cert_file {cert_file!r} could not be read: {e}") from e
    lines = [
        line.strip()
        for line in pem.splitlines()
        if line.strip() and "BEGIN CERTIFICATE" not in line and "END CERTIFICATE" not in line
    ]
    return "".join(lines) or None


class _EntityDescriptorDoc:
    """Holds rendered SP metadata XML; mirrors pysaml2's ``to_string``."""

    def __init__(self, xml: str) -> None:
        self._xml = xml

    def to_string(self) -> bytes:
        return self._xml.encode("utf-8")

    def to_xml(self) -> str:
        return self._xml

    def __str__(self) -> str:
        return self._xml


def entity_descriptor(config: SPConfig) -> _EntityDescriptorDoc:
    """Build this SP's ``<md:EntityDescriptor>`` from its config."""
    entity_id = config.entityid or ""
    cert_body = _read_cert_body(config.cert_file)

    key_descriptor = ""
    if cert_body:
        key_descriptor = (
            f'    <md:KeyDescriptor use="signing">\n'
            f'      <ds:KeyInfo xmlns:ds="{_DS}">\n'
            f"        <ds:X509Data>\n"
            f"          <ds:X509Certificate>{cert_body}</ds:X509Certificate>\n"
            f"        </ds:X509Data>\n"
            f"      </ds:KeyInfo>\n"
            f"    </md:KeyDescriptor>\n"
        )

    acs_xml = ""
    for index, (url, binding) in enumerate(config.acs_endpoints):
        acs_xml += (
            f'    <md:AssertionConsumerService Binding={quoteattr(binding)} '
            f"Location={quoteattr(url)} index=\"{index}\""
            f'{" isDefault=\"true\"" if index == 0 else ""}/>\n'
        )

    slo_xml = ""
    for url, binding in config.slo_endpoints:
        slo_xml += (
            f"    <md:SingleLogoutService Binding={quoteattr(binding)} Location={quoteattr(url)}/>\n"
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<md:EntityDescriptor xmlns:md="{_MD}" entityID={quoteattr(entity_id)}>\n'
        '  <md:SPSSODescriptor protocolSupportEnumeration='
        '"urn:oasis:names:tc:SAML:2.0:protocol" '
        'AuthnRequestsSigned="false" WantAssertionsSigned="false">\n'
        f"{key_descriptor}"
        f"{slo_xml}"
        f"{acs_xml}"
        "  </md:SPSSODescriptor>\n"
        "</md:EntityDescriptor>\n"
    )
    # escape() is applied to free text only; attribute values use quoteattr.
    _ = escape  # kept for clarity; endpoints/cert are controlled config values
    return _EntityDescriptorDoc(xml)
