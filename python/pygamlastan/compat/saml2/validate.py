"""Validation exception names used by existing pysaml2 integrations."""

from . import SAMLError


class ResponseLifetimeExceed(SAMLError):
    """The response or assertion is no longer valid."""


class ToEarly(SAMLError):
    """The response or assertion is not valid yet."""


__all__ = ["ResponseLifetimeExceed", "ToEarly"]
