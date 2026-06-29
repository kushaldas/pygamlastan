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
import binascii
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
    """Inverse of :func:`code` - rebuild a :class:`NameID` from its string.

    Any corruption after the ``pgc1:`` marker (bad base64, non-UTF-8 bytes,
    malformed JSON) is normalized into a single :class:`ValueError`, so callers
    need not know the encoding details.
    """
    if not value.startswith(_PREFIX):
        raise ValueError("not a pygamlastan-compat encoded NameID")
    body = value[len(_PREFIX) :]
    # Restore any stripped padding, then decode strictly: validate=True makes any
    # non-alphabet character (e.g. injected punctuation) fail closed instead of
    # being silently discarded, honouring the "corruption -> ValueError" contract.
    if len(body) % 4:
        body += "=" * (4 - len(body) % 4)
    try:
        raw = base64.b64decode(body.encode("ascii"), altchars=b"-_", validate=True)
        payload = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"corrupt pygamlastan-compat NameID: {e}") from e
    if not isinstance(payload, dict):
        # valid JSON but not an object (e.g. a list/number) - still corruption.
        raise ValueError("corrupt pygamlastan-compat NameID: payload is not an object")

    def _field(key: str) -> str | None:
        # Each NameID field must be a string or absent/null; a non-string value
        # (list/int/...) is corruption, normalized to ValueError per the contract
        # so NameID.text et al. never become non-string.
        val = payload.get(key)
        if val is not None and not isinstance(val, str):
            raise ValueError(
                f"corrupt pygamlastan-compat NameID: field {key!r} is not a string"
            )
        return val

    return NameID(
        text=_field("v"),
        format=_field("f"),
        name_qualifier=_field("nq"),
        sp_name_qualifier=_field("spnq"),
        sp_provided_id=_field("spid"),
    )
