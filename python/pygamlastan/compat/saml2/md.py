"""SAML metadata namespace compatibility constant."""

NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata"

from .metadata import EntityDescriptor

__all__ = ["NAMESPACE", "EntityDescriptor"]
