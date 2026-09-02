"""Minimal mutable SAML protocol value objects used to configure requests."""

from __future__ import annotations

from typing import Any

NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol"


class AuthnRequest:
    """Marker matching pysaml2's generated AuthnRequest class."""


class IDPEntry:
    """One IdP allowed by an AuthnRequest ``IDPList``."""

    def __init__(self, provider_id: str | None = None, **kwargs: Any) -> None:
        self.provider_id = provider_id


class IDPList:
    """Mutable collection of IdP entries used inside request scoping."""

    def __init__(self, idp_entry: list[IDPEntry] | None = None, **kwargs: Any) -> None:
        self.idp_entry = list(idp_entry or [])


class Scoping:
    """Subset of pysaml2's mutable AuthnRequest scoping value object."""

    def __init__(
        self,
        idp_list: IDPList | None = None,
        proxy_count: int | None = None,
        requester_id: list[Any] | None = None,
        **kwargs: Any,
    ) -> None:
        self.idp_list = idp_list
        self.proxy_count = proxy_count
        self.requester_id = list(requester_id or [])


__all__ = ["NAMESPACE", "AuthnRequest", "IDPEntry", "IDPList", "Scoping"]
