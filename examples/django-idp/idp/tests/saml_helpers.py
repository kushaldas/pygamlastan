"""Real keys and browser-binding helpers for SAML integration tests."""
import datetime
from html.parser import HTMLParser
from types import SimpleNamespace
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pygamlastan import bindings, core, crypto, xml

from idp import slo


def make_config(base, role="idp"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SLO test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return SimpleNamespace(
        base_url=base, entity_id=f"{base}/{role}/metadata", slo_url=f"{base}/{role}/slo/",
        sso_url=f"{base}/{role}/sso/", acs_url=f"{base}/{role}/acs/",
        metadata_url=f"{base}/{role}/metadata", error_url=f"{base}/{role}/error",
        nameid_secret="test-secret", support_email="", scope="example.org",
        key_pem=key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        cert_pem=pem, cert_b64="".join(pem.decode().splitlines()[1:-1]),
    )


def sp_metadata(cfg, binding=None, response_location=None, extra_cert=None):
    keys = f'<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cfg.cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
    if extra_cert:
        keys = keys.replace(cfg.cert_b64, extra_cert) + keys
    endpoints = "".join(
        f'<md:SingleLogoutService Binding="{b}" Location="{cfg.slo_url}"' +
        (f' ResponseLocation="{response_location}"' if response_location else '') + '/>'
        for b in ([binding] if binding else [core.BINDING_HTTP_REDIRECT, core.BINDING_HTTP_POST])
    )
    return (f'<md:EntityDescriptor xmlns:md="{core.SAML_METADATA_NS}" xmlns:ds="{core.XMLDSIG_NS}" entityID="{cfg.entity_id}">'
            f'<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{keys}{endpoints}'
            f'<md:AssertionConsumerService Binding="{core.BINDING_HTTP_POST}" Location="{cfg.acs_url}" index="0"/>'
            '</md:SPSSODescriptor></md:EntityDescriptor>')


class FormParser(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.inputs = {}
        self.action = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.action = attrs.get("action")
        if tag == "input" and "name" in attrs:
            self.inputs[attrs["name"]] = attrs.get("value", "")


def deliver(client, message, cfg, binding=core.BINDING_HTTP_REDIRECT, relay=None, signed=True, path="/idp/slo/", text=None):
    text = message.to_xml() if text is None else text
    if binding == core.BINDING_HTTP_REDIRECT:
        url = bindings.redirect_encode(text.encode(), hasattr(message, "name_id"), "https://example.org" + path,
                                       relay_state=relay, signer=crypto.SamlSigner.from_pem(cfg.key_pem) if signed else None,
                                       sig_alg="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" if signed else None)
        return client.get(path + "?" + urlsplit(url).query)
    if signed:
        text = slo.sign_message(text, message.id, cfg)
    field = "SAMLRequest" if hasattr(message, "name_id") else "SAMLResponse"
    import base64
    data = {field: base64.b64encode(text.encode()).decode()}
    if relay is not None:
        data["RelayState"] = relay
    return client.post(path, data)


def decoded_response(response):
    if response.status_code == 302:
        decoded = bindings.redirect_decode(urlsplit(response["Location"]).query)
    else:
        decoded = bindings.post_decode(list(FormParser(response.content.decode()).inputs.items()))
    text = decoded.saml_xml.decode()
    message = xml.parse_logout_request(text) if decoded.is_request else xml.parse_logout_response(text)
    return decoded, message
