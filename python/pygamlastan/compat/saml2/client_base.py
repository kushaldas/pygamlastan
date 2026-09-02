"""Exceptions shared by pysaml2's client base classes."""


class LogoutError(Exception):
    """Raised when no configured peer can complete Single Logout."""


__all__ = ["LogoutError"]
