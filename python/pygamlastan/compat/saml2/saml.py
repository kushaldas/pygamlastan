"""``saml2.saml`` shims: the NameID / Subject value objects and the format
constants that SP code references.

These are thin value holders, deliberately independent of the pygamlastan core
``NameId`` (which is a frozen pyclass). The shim ``NameID`` mirrors the small
pysaml2 ``saml.NameID`` surface that eduID touches: a ``.text`` payload plus
``format`` / ``name_qualifier`` / ``sp_name_qualifier`` attributes.
"""

from __future__ import annotations

from pygamlastan.core import (
    NAMEID_ENTITY,
    NAMEID_PERSISTENT,
    NAMEID_TRANSIENT,
    NAMEID_UNSPECIFIED,
)
from pygamlastan.core import NameId as _CoreNameId

# pysaml2 spells these NAMEID_FORMAT_* / NAME_FORMAT_*; the values are the
# standard SAML URNs, identical to pygamlastan's own constants.
NAMEID_FORMAT_TRANSIENT = NAMEID_TRANSIENT
NAMEID_FORMAT_PERSISTENT = NAMEID_PERSISTENT
NAMEID_FORMAT_UNSPECIFIED = NAMEID_UNSPECIFIED
NAMEID_FORMAT_ENTITY = NAMEID_ENTITY
NAME_FORMAT_URI = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
NAME_FORMAT_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"


class NameID:
    """pysaml2-shaped NameID value object.

    pysaml2 stores the identifier text in ``.text`` and the qualifiers as
    attributes. We keep the same shape so call sites such as
    ``NameID(format=..., text=...)`` and attribute reads keep working.
    """

    def __init__(
        self,
        text: str | None = None,
        format: str | None = None,
        name_qualifier: str | None = None,
        sp_name_qualifier: str | None = None,
        sp_provided_id: str | None = None,
    ) -> None:
        # pysaml2 sometimes carries surrounding whitespace from XML text nodes.
        self.text = text.strip() if isinstance(text, str) else text
        self.format = format
        self.name_qualifier = name_qualifier
        self.sp_name_qualifier = sp_name_qualifier
        self.sp_provided_id = sp_provided_id

    @classmethod
    def from_core(cls, name_id: _CoreNameId) -> NameID:
        """Build a shim NameID from a pygamlastan core ``NameId``."""
        return cls(
            text=name_id.value,
            format=name_id.format,
            name_qualifier=name_id.name_qualifier,
            sp_name_qualifier=name_id.sp_name_qualifier,
            sp_provided_id=name_id.sp_provided_id,
        )

    def to_core(self) -> _CoreNameId:
        """Convert back to a pygamlastan core ``NameId`` for binding calls."""
        return _CoreNameId(
            self.text or "",
            format=self.format,
            name_qualifier=self.name_qualifier,
            sp_name_qualifier=self.sp_name_qualifier,
            sp_provided_id=self.sp_provided_id,
        )

    def __str__(self) -> str:
        return self.text or ""

    def __repr__(self) -> str:
        return (
            f"<NameID text={self.text!r} format={self.format!r} "
            f"sp_name_qualifier={self.sp_name_qualifier!r}>"
        )


class Subject:
    """pysaml2-shaped Subject wrapper around a :class:`NameID`."""

    def __init__(self, name_id: NameID | None = None) -> None:
        self.name_id = name_id

    def __repr__(self) -> str:
        return f"<Subject name_id={self.name_id!r}>"
