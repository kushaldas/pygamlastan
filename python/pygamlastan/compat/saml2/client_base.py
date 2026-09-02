"""Exceptions shared by pysaml2's client base classes."""

from . import SAMLError


class LogoutError(SAMLError):
    """Raised when no configured peer can complete Single Logout."""


__all__ = ["LogoutError"]
