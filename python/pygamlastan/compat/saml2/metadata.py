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
    # Extract only the FIRST certificate block: a full-chain PEM has several, and
    # concatenating all of them would produce an invalid X509Certificate body.
    body: list[str] = []
    in_cert = False
    for line in pem.splitlines():
        stripped = line.strip()
        if "BEGIN CERTIFICATE" in stripped:
            in_cert = True
            continue
        if "END CERTIFICATE" in stripped:
            break
        if in_cert and stripped:
            body.append(stripped)
    return "".join(body) or None


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
    if not config.entityid:
        raise ValueError("SPConfig.entityid is required to build SP metadata")
    entity_id = config.entityid
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

    # Advertise the SP's actual signing behaviour: it can sign AuthnRequests when
    # a key is configured, and it expects signed responses/assertions when
    # want_response_signed is set, so IdPs negotiate the right behaviour.
    authn_requests_signed = "true" if config.key_file else "false"
    want_assertions_signed = "true" if config.want_response_signed else "false"

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<md:EntityDescriptor xmlns:md="{_MD}" entityID={quoteattr(entity_id)}>\n'
        '  <md:SPSSODescriptor protocolSupportEnumeration='
        '"urn:oasis:names:tc:SAML:2.0:protocol" '
        f'AuthnRequestsSigned="{authn_requests_signed}" '
        f'WantAssertionsSigned="{want_assertions_signed}">\n'
        f"{key_descriptor}"
        f"{slo_xml}"
        f"{acs_xml}"
        "  </md:SPSSODescriptor>\n"
        "</md:EntityDescriptor>\n"
    )
    # escape() is applied to free text only; attribute values use quoteattr.
    _ = escape  # kept for clarity; endpoints/cert are controlled config values
    return _EntityDescriptorDoc(xml)
