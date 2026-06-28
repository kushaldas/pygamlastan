"""``saml2.s_utils`` shims: the DEFLATE + base64 helpers used by the HTTP
Redirect binding (and by tests that hand-craft redirect payloads).
"""

from __future__ import annotations

import base64
import zlib


def deflate_and_base64_encode(value: str | bytes) -> str:
    """RFC 1951 raw-DEFLATE then base64, as the SAML Redirect binding requires."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = compressor.compress(value) + compressor.flush()
    return base64.b64encode(deflated).decode("ascii")


def decode_base64_and_inflate(value: str | bytes) -> bytes:
    """Inverse of :func:`deflate_and_base64_encode`."""
    if isinstance(value, str):
        value = value.encode("ascii")
    return zlib.decompress(base64.b64decode(value), -15)
