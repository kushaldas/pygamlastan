# pygamlastan

Python bindings for [gamlastan](https://github.com/kushaldas/gamlastan) **0.5.0**, a
pure-Rust SAML 2.0 library - types, XML, crypto, metadata, bindings, security, and
profiles. Built with [PyO3](https://pyo3.rs) 0.29 + [maturin](https://www.maturin.rs)
(abi3, Python ≥ 3.10).

The binding mirrors gamlastan's modules as Python submodules:
`pygamlastan.{core, xml, crypto, bindings, metadata, security, profiles,
attribute_map, idp}`. Parsing converts gamlastan's zero-copy `*Ref` views to owned
values at the FFI boundary, so no Rust lifetime escapes into Python.

## Example - SP processes an IdP response

```python
from pygamlastan import xml, profiles, security, crypto

# Verify the response signature with the trusted IdP certificate.
verifier = crypto.SamlVerifier.from_cert(idp_cert_pem)
verified = verifier.verify_enveloped(response_xml)

parsed = xml.parse_response(response_xml)
result = profiles.process_response(
    parsed,
    security.SecurityConfig(),          # production defaults
    sp_entity_id="https://sp.example.org/sp",
    acs_url="https://sp.example.org/acs",
    expected_idp_entity_id="https://idp.example.org",
    expected_request_id="_req123",
    verified_signed_ids=verified.signed_reference_ids(),
    replay_cache=security.InMemoryReplayCache(),
)
print(result.name_id, result.attributes_dict())
```

## HSM / PKCS#11 signing

```python
from pygamlastan import crypto

prov = crypto.Pkcs11Provider("/usr/lib/softhsm/libsofthsm2.so")
session = prov.open_session("1234")
signer = crypto.SamlSigner.with_pkcs11(session.signer("saml-signing-key", "rsa-sha256"))
signed = signer.sign_enveloped(xml_with_signature_template)
```

> **Deploying with an HSM?** Prefer building the wheel in - or against - your
> target environment instead of relying on the generic prebuilt wheel. The
> compiled extension links the host's C/crypto stack, and your PKCS#11 module
> (SoftHSM2, kryoptic, or a vendor driver) is `dlopen`-ed at runtime from that
> same host. Building where your token tooling and system libraries live (e.g.
> `maturin build --release` on the target host or a container matching
> production) avoids glibc/loader and provider-ABI mismatches and lets you
> validate signing against the real module before shipping.

## Development

```console
uv venv
uv pip install --python .venv/bin/python maturin
VIRTUAL_ENV=$PWD/.venv .venv/bin/maturin develop --uv
.venv/bin/python -m pytest tests/
```

The PKCS#11 test self-skips unless SoftHSM2 (`softhsm2-util` + `pkcs11-tool`) is
installed; when present it provisions a throwaway token and signs for real.

## Documentation

You can read the [latest](https://pygamlastan.readthedocs.io/en/latest/) or the documentation (Sphinx 9.1) lives in `docs/`: installation, a quickstart, task
guides (SP/IdP integration, signing & HSM, bindings, metadata, attributes,
validation), and a per-module API reference. Build it with the project venv so the
package is importable:

```console
uv pip install --python .venv/bin/python --group docs
.venv/bin/python -m sphinx -b html docs docs/_build/html
# open docs/_build/html/index.html
```

## Type stubs

The package ships PEP 561 type information: `py.typed` plus one `.pyi` per submodule,
living in `python/pygamlastan/` (a maturin mixed Rust+Python layout where the compiled
extension is `pygamlastan._native`). The stubs are included in the wheel, so mypy /
pyright pick them up with no extra configuration.
