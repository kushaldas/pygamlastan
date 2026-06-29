"""``saml2.cache`` shim.

eduID subclasses ``saml2.cache.Cache`` for its IdentityCache, passing in a
dict-like backend. pysaml2's ``Cache`` stores per-(subject, entity) session
info with an expiry timestamp so it can drive Single Logout and validity checks.

This is a faithful dict-backed reimplementation of that contract: the same
``self._db[code(name_id)][entity_id] = (not_on_or_after, info)`` layout and the
same method semantics, so a subclass that sets ``self._db`` to a MutableMapping
(as eduID's ``IdentityCache`` does) gets working storage and expiry. The
pygamlastan SP flow itself derives logout targets from config/metadata rather
than this cache, but the store is real so subclasses behave as on pysaml2.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from .ident import code, decode


class ToOld(Exception):
    """Raised by :meth:`Cache.get` when an entry is past its expiry."""


# pysaml2 spells the class both ways; keep the alias for drop-in compatibility.
TooOld = ToOld


def _to_epoch(point: Any) -> float | None:
    """Coerce a stored ``not_on_or_after`` to epoch seconds (or None)."""
    if point is None:
        return None
    if isinstance(point, (int, float)):
        return float(point)
    if isinstance(point, datetime):
        return point.timestamp()
    if isinstance(point, str):
        try:
            return datetime.fromisoformat(point.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _expired(point: Any) -> bool:
    """True if the entry is past its expiry.

    ``None`` means "no expiry" (never expired). A real numeric timestamp -
    including ``0`` (pysaml2's reset value, which is in the past) - goes through
    the comparison. An unparseable non-``None`` value fails closed (expired), and
    ``_expired``/``_valid`` stay each other's inverse for every input.
    """
    if point is None:
        return False
    epoch = _to_epoch(point)
    if epoch is None:  # unparseable non-None -> fail closed
        return True
    return time.time() >= epoch


def _valid(point: Any) -> bool:
    """Inverse of :func:`_expired`: ``None`` is valid, unparseable fails closed."""
    if point is None:
        return True
    epoch = _to_epoch(point)
    if epoch is None:  # unparseable non-None -> fail closed
        return False
    return time.time() < epoch


class Cache:
    """Dict-backed stand-in for ``saml2.cache.Cache``.

    Subclasses (e.g. eduID's ``IdentityCache``) typically replace ``self._db``
    with their own MutableMapping in ``__init__``; the methods here operate on
    whatever ``_db`` is installed.
    """

    def __init__(self, filename: str | None = None) -> None:
        # Unlike pysaml2 there is no shelve-backed mode; a filename is accepted
        # for signature compatibility but storage is always in-memory unless a
        # subclass swaps in its own backend.
        self._db: dict[str, dict[str, tuple[Any, dict[str, Any]]]] = {}
        self._sync = False

    def delete(self, name_id: Any) -> None:
        del self._db[code(name_id)]

    def get_identity(
        self, name_id: Any, entities: Any = None, check_not_on_or_after: bool = True
    ) -> tuple[dict[str, Any], list[str]]:
        """Aggregate still-valid identity info; report timed-out entity ids."""
        # ``None`` means "default to every stored entity"; an explicitly empty
        # list is honoured as a request to aggregate over no entities.
        if entities is None:
            try:
                entities = list(self._db[code(name_id)].keys())
            except KeyError:
                return {}, []

        res: dict[str, Any] = {}
        oldees: list[str] = []
        for entity_id in entities:
            try:
                info = self.get(name_id, entity_id, check_not_on_or_after)
            except ToOld:
                oldees.append(entity_id)
                continue
            if not info:
                oldees.append(entity_id)
                continue
            for key, vals in info.get("ava", {}).items():
                if key in res:
                    res[key] = list(set(res[key]).union(set(vals)))
                else:
                    res[key] = vals
        return res, oldees

    def get(
        self, name_id: Any, entity_id: Any, check_not_on_or_after: bool = True
    ) -> dict[str, Any] | None:
        cni = code(name_id)
        timestamp, info = self._db[cni][entity_id]
        info = dict(info)
        if check_not_on_or_after and _expired(timestamp):
            raise ToOld(f"past {timestamp}")
        if "name_id" in info and isinstance(info["name_id"], str):
            info["name_id"] = decode(info["name_id"])
        return info or None

    def set(self, name_id: Any, entity_id: Any, info: Any, not_on_or_after: Any = 0) -> None:
        info = dict(info)
        if "name_id" in info and not isinstance(info["name_id"], str):
            # Encode the NameID actually carried in the payload (not the key
            # argument), so a payload with a different subject round-trips
            # consistently.
            info["name_id"] = code(info["name_id"])
        cni = code(name_id)
        if cni not in self._db:
            self._db[cni] = {}
        self._db[cni][entity_id] = (not_on_or_after, info)

    def reset(self, name_id: Any, entity_id: Any) -> None:
        self.set(name_id, entity_id, {}, 0)

    def entities(self, name_id: Any) -> list[str]:
        return list(self._db[code(name_id)].keys())

    def receivers(self, name_id: Any) -> list[str]:
        return self.entities(name_id)

    def active(self, name_id: Any, entity_id: Any) -> bool:
        try:
            timestamp, info = self._db[code(name_id)][entity_id]
        except KeyError:
            return False
        if not info:
            return False
        return _valid(timestamp)

    def subjects(self) -> list[Any]:
        return [decode(c) for c in self._db.keys()]
