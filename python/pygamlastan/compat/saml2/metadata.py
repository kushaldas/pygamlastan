"""pysaml2-compatible service-provider metadata generation."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from pygamlastan import metadata as _native_metadata
from pygamlastan.attribute_map import AttributeConverter

from .config import SPConfig

_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_XML = "http://www.w3.org/XML/1998/namespace"
_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
_ATTR_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

ET.register_namespace("md", _MD)
ET.register_namespace("ds", _DS)


def _read_cert_body(cert_file: str | None) -> str | None:
    if not cert_file:
        return None
    try:
        with open(cert_file, encoding="ascii") as fh:
            pem = fh.read()
    except OSError as exc:
        raise ValueError(
            f"configured certificate {cert_file!r} could not be read: {exc}"
        ) from exc
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
    encoded = "".join(body)
    if not encoded:
        raise ValueError(
            f"configured certificate {cert_file!r} contains no PEM certificate"
        )
    return encoded


def _localized(parent: ET.Element, tag: str, values: object) -> None:
    if not isinstance(values, (list, tuple)):
        return
    for item in values:
        if not isinstance(item, (list, tuple)) or not item:
            continue
        value = str(item[0])
        lang = str(item[1]) if len(item) > 1 and item[1] else None
        element = ET.SubElement(parent, f"{{{_MD}}}{tag}")
        if lang:
            element.set(f"{{{_XML}}}lang", lang)
        element.text = value


def _key_descriptor(parent: ET.Element, use: str, cert_body: str) -> None:
    descriptor = ET.SubElement(parent, f"{{{_MD}}}KeyDescriptor", {"use": use})
    key_info = ET.SubElement(descriptor, f"{{{_DS}}}KeyInfo")
    x509_data = ET.SubElement(key_info, f"{{{_DS}}}X509Data")
    ET.SubElement(x509_data, f"{{{_DS}}}X509Certificate").text = cert_body


class EntityDescriptor:
    """Rendered SP metadata with pysaml2's ``to_string``/``to_xml`` API."""

    def __init__(self, xml: str) -> None:
        self._xml = xml

    def to_string(self) -> bytes:
        return self._xml.encode("utf-8")

    def to_xml(self) -> str:
        return self._xml

    def __str__(self) -> str:
        return self._xml


def entity_descriptor(config: SPConfig) -> EntityDescriptor:
    """Build and natively validate this SP's metadata document."""
    if not config.entityid:
        raise ValueError("SPConfig.entityid is required to build SP metadata")

    root = ET.Element(f"{{{_MD}}}EntityDescriptor", {"entityID": config.entityid})
    descriptor = ET.SubElement(
        root,
        f"{{{_MD}}}SPSSODescriptor",
        {
            "protocolSupportEnumeration": _PROTOCOL,
            "AuthnRequestsSigned": str(config.authn_requests_signed).lower(),
            "WantAssertionsSigned": str(config.want_assertions_signed).lower(),
        },
    )

    signing_cert = _read_cert_body(config.cert_file)
    if signing_cert:
        _key_descriptor(descriptor, "signing", signing_cert)
    seen_encryption_certs: set[str] = set()
    for pair in config.encryption_keypairs:
        cert = _read_cert_body(pair.get("cert_file"))
        if cert and cert not in seen_encryption_certs:
            _key_descriptor(descriptor, "encryption", cert)
            seen_encryption_certs.add(cert)

    for url, binding in config.slo_endpoints:
        ET.SubElement(
            descriptor,
            f"{{{_MD}}}SingleLogoutService",
            {"Binding": binding, "Location": url},
        )

    formats = config.name_id_format
    if isinstance(formats, str):
        formats = [formats]
    for value in formats or []:
        ET.SubElement(descriptor, f"{{{_MD}}}NameIDFormat").text = str(value)

    for offset, (url, binding) in enumerate(config.acs_endpoints):
        attributes = {
            "Binding": binding,
            "Location": url,
            "index": str(offset + 1),
        }
        if offset == 0:
            attributes["isDefault"] = "true"
        ET.SubElement(descriptor, f"{{{_MD}}}AssertionConsumerService", attributes)

    requested = [(name, True) for name in config.required_attributes] + [
        (name, False) for name in config.optional_attributes
    ]
    if requested:
        service = ET.SubElement(
            descriptor, f"{{{_MD}}}AttributeConsumingService", {"index": "1"}
        )
        service_name = ET.SubElement(service, f"{{{_MD}}}ServiceName")
        service_name.set(f"{{{_XML}}}lang", "en")
        service_name.text = config.name or config.entityid
        converter = AttributeConverter.from_static("saml_uri")
        for local_name, required in requested:
            wire_name = converter.to_wire_name(local_name) or local_name
            ET.SubElement(
                service,
                f"{{{_MD}}}RequestedAttribute",
                {
                    "Name": wire_name,
                    "NameFormat": _ATTR_URI,
                    "FriendlyName": local_name,
                    "isRequired": str(required).lower(),
                },
            )

    if config.organization:
        organization = ET.SubElement(root, f"{{{_MD}}}Organization")
        _localized(organization, "OrganizationName", config.organization.get("name"))
        _localized(
            organization,
            "OrganizationDisplayName",
            config.organization.get("display_name"),
        )
        _localized(organization, "OrganizationURL", config.organization.get("url"))

    contact_fields = {
        "given_name": "GivenName",
        "sur_name": "SurName",
        "company": "Company",
        "email_address": "EmailAddress",
        "telephone_number": "TelephoneNumber",
    }
    for contact in config.contact_person:
        element = ET.SubElement(
            root,
            f"{{{_MD}}}ContactPerson",
            {"contactType": str(contact.get("contact_type", "technical"))},
        )
        for key, tag in contact_fields.items():
            value = contact.get(key)
            if value:
                ET.SubElement(element, f"{{{_MD}}}{tag}").text = str(value)

    xml = ET.tostring(root, encoding="unicode", xml_declaration=True)
    parsed = _native_metadata.parse_entity(xml)
    _native_metadata.validate_entity(parsed)
    return EntityDescriptor(xml)


__all__ = ["EntityDescriptor", "entity_descriptor"]
