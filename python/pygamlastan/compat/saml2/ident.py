"""``saml2.ident`` shims: ``code`` / ``decode`` round-trip a NameID to and from
an opaque string for storage in a session.

pysaml2 serialises a NameID to its own quoted-attribute string. The exact wire
form is private to pysaml2 and never leaves the deployment (it is stored in the
user session and handed back to the same library), so the shim uses its own
compact, self-describing encoding: a versioned base64url-wrapped JSON object.
Both ends are this shim, so the round-trip is all that matters.
"""

from __future__ import annotations

import base64
import json

from .saml import NameID

_PREFIX = "pgc1:"  # pygamlastan-compat v1 marker


def code(name_id: NameID) -> str:
    """Serialise a :class:`NameID` to an opaque, session-storable string."""
    payload = {
        "v": name_id.text,
        "f": name_id.format,
        "nq": name_id.name_qualifier,
        "spnq": name_id.sp_name_qualifier,
        "spid": name_id.sp_provided_id,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return _PREFIX + base64.urlsafe_b64encode(raw).decode("ascii")


def decode(value: str) -> NameID:
    """Inverse of :func:`code` - rebuild a :class:`NameID` from its string."""
    if not value.startswith(_PREFIX):
        raise ValueError("not a pygamlastan-compat encoded NameID")
    raw = base64.urlsafe_b64decode(value[len(_PREFIX) :].encode("ascii"))
    payload = json.loads(raw.decode("utf-8"))
    return NameID(
        text=payload.get("v"),
        format=payload.get("f"),
        name_qualifier=payload.get("nq"),
        sp_name_qualifier=payload.get("spnq"),
        sp_provided_id=payload.get("spid"),
    )
