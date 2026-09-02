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


class RequestVersionTooLow(Exception):
    """The response uses an unsupported SAML version."""


class SignatureError(AssertionError):
    """The response signature is missing or invalid.

    pysaml2 keeps signature failures outside the status-error hierarchy.
    Inheriting :class:`AssertionError` additionally preserves the legacy catch
    used by eduID without making djangosaml2's earlier ``StatusError`` handler
    swallow this more specific exception.
    """


class StatusAuthnFailed(StatusError):
    """The IdP reported AuthnFailed."""


class StatusNoAuthnContext(StatusError):
    """The IdP could not satisfy the requested authentication context."""


class StatusRequestDenied(StatusError):
    """The IdP denied the request."""


@lru_cache(maxsize=1)
def _converter() -> _attr.AttributeConverterSet:
    # The default OID<->friendly-name maps, built once per process.
    return _attr.AttributeConverterSet.with_default_maps()


class _SubjectConfirmationDataAdapter:
    """Expose native confirmation data under pysaml2 attribute names."""

    def __init__(self, value: Any) -> None:
        self._value = value

    @property
    def not_on_or_after(self) -> Any:
        return self._value.not_on_or_after


class _SubjectConfirmationAdapter:
    """Adapt one native bearer confirmation for djangosaml2 consumers."""

    def __init__(self, value: Any) -> None:
        self._value = value

    @property
    def method(self) -> str:
        return self._value.method

    @property
    def subject_confirmation_data(self) -> _SubjectConfirmationDataAdapter | None:
        data = self._value.subject_confirmation_data
        return _SubjectConfirmationDataAdapter(data) if data is not None else None


class _SubjectAdapter:
    """Adapt a native Subject and its plural confirmation collection."""

    def __init__(self, value: Any) -> None:
        self._value = value

    @property
    def subject_confirmation(self) -> list[_SubjectConfirmationAdapter]:
        return [
            _SubjectConfirmationAdapter(item)
            for item in self._value.subject_confirmations
        ]


class _AssertionAdapter:
    """Expose the assertion members read by djangosaml2's ACS view."""

    def __init__(self, value: Any) -> None:
        self._value = value

    @property
    def id(self) -> str:
        return self._value.id

    @property
    def subject(self) -> _SubjectAdapter | None:
        subject = self._value.subject
        return _SubjectAdapter(subject) if subject is not None else None


class AuthnResponse:
    """pysaml2-shaped wrapper over a pygamlastan ``AuthnResult``."""

    def __init__(
        self,
        result: _AuthnResult,
        in_response_to: str | None,
        assertion: Any = None,
        came_from: Any = None,
        legacy_attribute_values: dict[str, list[str]] | None = None,
    ) -> None:
        self._result = result
        self._in_response_to = in_response_to
        self._came_from = came_from
        self._legacy_attribute_values = legacy_attribute_values or {}
        self.assertion = _AssertionAdapter(assertion) if assertion is not None else None

    def session_id(self) -> str | None:
        """Return the AuthnRequest ID echoed by the response."""
        # pysaml2's session_id() is the request id echoed in InResponseTo.
        return self._in_response_to

    @property
    def ava(self) -> dict[str, list[str]]:
        """Return assertion attributes converted to local friendly names."""
        local = _converter().to_local(self._result.attributes)
        values = {la.name: list(la.values) for la in local}
        # Only fill empty/missing native values. A well-formed typed value
        # remains authoritative over the narrow legacy recovery path.
        for name, recovered in self._legacy_attribute_values.items():
            if not values.get(name):
                values[name] = list(recovered)
        return values

    def get_subject(self) -> NameID:
        """Return the authenticated subject as a pysaml2-shaped NameID."""
        r = self._result
        return NameID(
            text=r.name_id,
            format=r.name_id_format,
            name_qualifier=r.name_qualifier,
            sp_name_qualifier=r.sp_name_qualifier,
        )

    def session_info(self) -> dict[str, Any]:
        """Return the session dictionary expected by pysaml2 SP callers."""
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
            "came_from": self._came_from,
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
        """Report whether the SAML LogoutResponse carried Success status."""
        return self._success


__all__ = [
    "AuthnResponse",
    "LogoutResponse",
    "RequestVersionTooLow",
    "SignatureError",
    "StatusAuthnFailed",
    "StatusError",
    "StatusNoAuthnContext",
    "StatusRequestDenied",
    "UnsolicitedResponse",
]
