"""``saml2.cache`` shim.

eduID subclasses ``saml2.cache.Cache`` for its IdentityCache, passing in a
dict-like backend. The real pysaml2 ``Cache`` stores per-subject identity and
expiry data so it can drive Single Logout. The pygamlastan SP flow does not rely
on pysaml2's internal identity bookkeeping (logout targets come from config /
metadata), so this shim is a minimal dict-backed store that satisfies the base
class contract eduID's subclass expects.
"""

from __future__ import annotations

from typing import Any


class Cache:
    """Minimal dict-backed stand-in for ``saml2.cache.Cache``.

    Subclasses (e.g. eduID's ``IdentityCache``) set ``self._db`` to a
    MutableMapping in their own ``__init__``; the methods here operate on
    whatever ``_db`` the subclass installed, falling back to a plain dict.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._db: dict[str, Any] = {}
        self._sync = False

    def get_identity(
        self, name_id: Any, entities: Any = None, check_not_on_or_after: bool = True
    ) -> tuple[dict[str, Any], list[str]]:
        """Return (identity-attributes, list-of-entity-ids-still-valid)."""
        return ({}, [])

    def get(self, name_id: Any, entity_id: Any, check_not_on_or_after: bool = True) -> dict[str, Any]:
        return {}

    def set(self, name_id: Any, entity_id: Any, info: Any, not_on_or_after: int = 0) -> None:
        return None

    def reset(self, name_id: Any, entity_id: Any) -> None:
        return None

    def entities(self, name_id: Any) -> list[str]:
        return []

    def receivers(self, name_id: Any) -> list[str]:
        return []

    def active(self, name_id: Any, entity_id: Any) -> bool:
        return False

    def subjects(self) -> list[Any]:
        return []
