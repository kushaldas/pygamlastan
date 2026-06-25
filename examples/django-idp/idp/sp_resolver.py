"""Resolve an SP entityID to its metadata, with no local SP database.

Two sources, tried in order:

  1. Local files - signed/self-contained metadata XML in ``SAML_IDP_METADATA_DIR``
     (a single ``<EntityDescriptor>`` or an ``<EntitiesDescriptor>`` aggregate).
     These are **trusted as provided**: the SP's own keys are embedded in the
     file and you placed it on disk, so it is not re-verified against a federation
     cert. Parsed once at first use and indexed by entityID in memory; restart the
     app to reload changed files.
  2. MDQ - if ``SAML_IDP_MDQ_URL`` is set, an unknown entityID is fetched on
     demand from the Metadata Query server and **mandatorily signature-verified**
     against ``SAML_IDP_METADATA_CERT`` before being trusted.

Nothing is written to a database.
"""
from __future__ import annotations

import logging
import urllib.parse
import urllib.request
from functools import lru_cache
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from pygamlastan import crypto, metadata

log = logging.getLogger(__name__)

# entityID -> single-entity metadata XML, for MDQ results.
_mdq_cache: dict[str, str | None] = {}


@lru_cache(maxsize=1)
def _verifier():
    cert_path = settings.SAML_IDP_METADATA_CERT
    if not cert_path:
        raise ImproperlyConfigured(
            "SAML_IDP_METADATA_CERT is required to use MDQ: remote metadata "
            "signature verification is mandatory."
        )
    return crypto.SamlVerifier.from_cert(Path(cert_path).read_bytes())


def _verify(xml_text: str) -> bool:
    """True only if the metadata's enveloped signature verifies against the cert."""
    try:
        return _verifier().verify_enveloped(xml_text).is_valid()
    except Exception as exc:  # noqa: BLE001
        log.warning("metadata signature verification error: %s", exc)
        return False


@lru_cache(maxsize=1)
def _file_index() -> dict:
    """entityID -> EntityDescriptor for SPs in the local metadata files.

    Cached for the process lifetime - this is the "loaded at startup" path. Local
    files are trusted as provided (the SP keys live in the file); they are not
    re-verified against a federation cert.
    """
    index: dict = {}
    md_dir = Path(settings.SAML_IDP_METADATA_DIR)
    if not md_dir.is_dir():
        return index
    for path in sorted(md_dir.glob("*.xml")):
        xml_text = path.read_text()
        try:
            entities = metadata.parse_entities(xml_text)
        except Exception:  # noqa: BLE001 - not an aggregate? try a single entity
            try:
                entities = [metadata.parse_entity(xml_text)]
            except Exception as exc:  # noqa: BLE001
                log.warning("could not parse metadata %s: %s", path, exc)
                continue
        for entity in entities:
            if entity.is_sp():
                index[entity.entity_id] = entity
    log.info("loaded %d local SP(s) from %s", len(index), md_dir)
    return index


def _mdq_fetch(entity_id: str) -> str | None:
    base = settings.SAML_IDP_MDQ_URL.rstrip("/")
    # MDQ single-entity request: /entities/{url-encoded entityID}
    url = f"{base}/entities/{urllib.parse.quote(entity_id, safe='')}"
    request = urllib.request.Request(
        url, headers={"Accept": "application/samlmetadata+xml"}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:  # noqa: S310
            xml_text = resp.read().decode()
    except Exception as exc:  # noqa: BLE001
        log.warning("MDQ lookup for %s failed: %s", entity_id, exc)
        return None
    if not _verify(xml_text):
        log.warning("MDQ metadata for %s failed signature verification; rejecting", entity_id)
        return None
    return xml_text


def resolve(entity_id: str | None) -> str | None:
    """Return single-entity SP metadata XML for ``entity_id``, or None.

    Local files first (trusted), then MDQ (signature-verified).
    """
    if not entity_id:
        return None

    entity = _file_index().get(entity_id)
    if entity is not None:
        return entity.to_xml()

    if settings.SAML_IDP_MDQ_URL:
        if entity_id not in _mdq_cache:
            _mdq_cache[entity_id] = _mdq_fetch(entity_id)
        return _mdq_cache[entity_id]

    return None


def file_sp_count() -> int:
    return len(_file_index())


def reload() -> None:
    """Forget cached files / MDQ results / the loaded verifier."""
    _file_index.cache_clear()
    _mdq_cache.clear()
    _verifier.cache_clear()
