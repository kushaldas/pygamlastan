"""``saml2.sigver`` shim.

pygamlastan does XML-DSig natively in Rust (via bergshamra) and never shells out
to the ``xmlsec1`` binary, so there is no binary to locate. ``get_xmlsec_binary``
is retained only so existing imports and config-loading code keep working; it
returns ``None`` (no external signer is used).
"""

from __future__ import annotations

from typing import Any


def get_xmlsec_binary(paths: Any = None) -> None:
    """No-op: pygamlastan signs/verifies in-process, with no xmlsec1 binary."""
    return None
