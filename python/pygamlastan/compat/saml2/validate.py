"""Validation exception names used by existing pysaml2 integrations."""


class ResponseLifetimeExceed(Exception):
    """The response or assertion is no longer valid."""


class ToEarly(Exception):
    """The response or assertion is not valid yet."""


__all__ = ["ResponseLifetimeExceed", "ToEarly"]
