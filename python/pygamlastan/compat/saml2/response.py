"""``saml2.response`` shims: the response wrappers and exception types SP code
imports.

``AuthnResponse`` wraps a pygamlastan ``profiles.AuthnResult`` and reproduces the
two methods eduID calls: ``session_id()`` and ``session_info()`` (the latter
returning pysaml2's ``authn_info`` / ``ava`` / ``issuer`` / ``name_id`` /
``not_on_or_after`` / ``session_index`` dict).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from pygamlastan import attribute_map as _attr
from pygamlastan.profiles import AuthnResult as _AuthnResult

from .saml import NameID


class StatusError(Exception):
    """Raised when the SAML Response carries a non-Success status."""


class UnsolicitedResponse(Exception):
    """Raised when a Response's InResponseTo is not in the outstanding set."""


@lru_cache(maxsize=1)
def _converter() -> _attr.AttributeConverterSet:
    # The default OID<->friendly-name maps, built once per process.
    return _attr.AttributeConverterSet.with_default_maps()


class AuthnResponse:
    """pysaml2-shaped wrapper over a pygamlastan ``AuthnResult``."""

    def __init__(self, result: _AuthnResult, in_response_to: str | None) -> None:
        self._result = result
        self._in_response_to = in_response_to

    def session_id(self) -> str | None:
        # pysaml2's session_id() is the request id echoed in InResponseTo.
        return self._in_response_to

    @property
    def ava(self) -> dict[str, list[str]]:
        local = _converter().to_local(self._result.attributes)
        return {la.name: list(la.values) for la in local}

    def get_subject(self) -> NameID:
        r = self._result
        return NameID(
            text=r.name_id,
            format=r.name_id_format,
            name_qualifier=r.name_qualifier,
            sp_name_qualifier=r.sp_name_qualifier,
        )

    def session_info(self) -> dict[str, Any]:
        r = self._result
        not_on_or_after = None
        if r.session_not_on_or_after is not None:
            # pysaml2 expressed this as epoch seconds.
            not_on_or_after = int(r.session_not_on_or_after.timestamp())
        return {
            "ava": self.ava,
            "name_id": self.get_subject(),
            # pysaml2 carries the SP-supplied return target here; the eduID flow
            # tracks that itself (OutstandingQueriesCache), so it is always None.
            "came_from": None,
            "issuer": r.idp_entity_id,
            "not_on_or_after": not_on_or_after,
            "authn_info": [
                (
                    r.authn_context_class_ref,
                    list(r.authenticating_authorities),
                    r.authn_instant.isoformat(),
                )
            ],
            "session_index": r.session_index,
        }


class LogoutResponse:
    """pysaml2-shaped wrapper over a pygamlastan core ``LogoutResponse``."""

    def __init__(self, success: bool, in_response_to: str | None = None) -> None:
        self._success = success
        self.in_response_to = in_response_to

    def status_ok(self) -> bool:
        return self._success
