"""Small pysaml2-shaped metadata-store facade.

The native metadata parser deliberately exposes typed ``EntityDescriptor``
objects.  Existing pysaml2 consumers, notably djangosaml2, instead navigate a
``MetadataStore`` through ``.metadata``, ``.service()``, and ``.name()``.  This
module adapts those reads without reintroducing pysaml2's XML object model.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

from pygamlastan.metadata import EntityDescriptor


class SourceNotFound(Exception):
    """Raised when a configured metadata source cannot be resolved."""


class MetaDataMDX:
    """Marker base matching pysaml2's on-demand MDQ metadata source.

    Network MDQ fetching is intentionally outside the local compatibility
    store.  The class exists for ``isinstance`` checks and custom integrations
    may subclass it and implement ``__getitem__``.
    """


class _LocalMetadataSource:
    """One parsed local metadata document, possibly containing many entities."""

    def __init__(self, entities: list[EntityDescriptor]) -> None:
        self.entities = {entity.entity_id: entity for entity in entities}

    def any(self, descriptor: str, service: str) -> dict[str, Any]:
        if descriptor != "idpsso_descriptor":
            return {}
        result: dict[str, Any] = {}
        for entity_id, entity in self.entities.items():
            if not entity.is_idp():
                continue
            endpoints = _service_endpoints(entity, service)
            if endpoints:
                result[entity_id] = endpoints
        return result


def _service_endpoints(
    entity: EntityDescriptor, service: str, role: str = "idp"
) -> list[Any]:
    """Return native endpoint records for one metadata service and role."""
    if service == "single_sign_on_service":
        return list(entity.single_sign_on_services()) if role == "idp" else []
    if service == "single_logout_service":
        return list(entity.single_logout_services(role))
    return []


class MetadataStore(Mapping[str, EntityDescriptor]):
    """Mapping plus the metadata query methods used by djangosaml2."""

    def __init__(self) -> None:
        self._entities: dict[str, EntityDescriptor] = {}
        self.metadata: dict[str, _LocalMetadataSource | MetaDataMDX] = {}

    def add_source(self, source: str, entities: list[EntityDescriptor]) -> None:
        """Register the entities parsed from one local metadata source."""
        seen: set[str] = set()
        duplicates: set[str] = set()
        for entity in entities:
            if entity.entity_id in seen:
                duplicates.add(entity.entity_id)
            seen.add(entity.entity_id)
        if duplicates:
            raise ValueError(
                "duplicate metadata entity id(s): " + ", ".join(sorted(duplicates))
            )

        local = _LocalMetadataSource(entities)
        duplicates = seen.intersection(self._entities)
        if duplicates:
            raise ValueError(
                "duplicate metadata entity id(s): " + ", ".join(sorted(duplicates))
            )
        self.metadata[source] = local
        self._entities.update(local.entities)

    def __getitem__(self, entity_id: str) -> EntityDescriptor:
        return self._entities[entity_id]

    def __iter__(self) -> Iterator[str]:
        return iter(self._entities)

    def __len__(self) -> int:
        return len(self._entities)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MetadataStore):
            return self._entities == other._entities
        if isinstance(other, Mapping):
            return self._entities == dict(other)
        return NotImplemented

    def name(self, entity_id: str, langpref: str = "en") -> str:
        """Return the preferred IdP display name, falling back to its entity ID."""
        entity = self._entities.get(entity_id)
        if entity is None:
            raise UnknownSystemEntity(entity_id)
        info = entity.ui_info("idp")
        if info is not None:
            names = list(info.display_names)
            for lang, value in names:
                if lang == langpref:
                    return value
            if names:
                return names[0][1]
        return entity_id

    def service(
        self,
        entity_id: str,
        descriptor: str,
        service: str,
        binding: str | None = None,
    ) -> dict[str, list[dict[str, Any]]] | list[dict[str, Any]]:
        """Return endpoint records, optionally filtered to one binding."""
        entity = self._entities.get(entity_id)
        if entity is None:
            raise UnknownSystemEntity(entity_id)
        if descriptor == "idpsso_descriptor" and entity.is_idp():
            role = "idp"
        elif descriptor == "spsso_descriptor" and entity.is_sp():
            role = "sp"
        else:
            raise UnknownSystemEntity(entity_id)
        records = [
            {
                "binding": endpoint.binding,
                "location": endpoint.location,
                "response_location": endpoint.response_location,
            }
            for endpoint in _service_endpoints(entity, service, role)
            if binding is None or endpoint.binding == binding
        ]
        if binding is not None:
            return records
        grouped: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            grouped.setdefault(record["binding"], []).append(record)
        return grouped

    def single_sign_on_service(
        self, entity_id: str, binding: str | None = None
    ) -> dict[str, list[dict[str, Any]]] | list[dict[str, Any]]:
        """Return SSO endpoints, optionally restricted to one binding."""
        return self.service(
            entity_id,
            "idpsso_descriptor",
            "single_sign_on_service",
            binding,
        )

    def single_logout_service(
        self,
        entity_id: str,
        binding: str | None = None,
        typ: str | None = None,
    ) -> dict[str, list[dict[str, Any]]] | list[dict[str, Any]]:
        """Return logout endpoints for the requested descriptor type."""
        if typ is None:
            raise AttributeError("Missing type specification")
        return self.service(
            entity_id,
            f"{typ}_descriptor",
            "single_logout_service",
            binding,
        )

    def with_descriptor(self, descriptor: str) -> dict[str, EntityDescriptor]:
        """Return entities that publish the requested IdP or SP descriptor."""
        if descriptor == "idpsso":
            return {
                key: value for key, value in self._entities.items() if value.is_idp()
            }
        if descriptor == "spsso":
            return {
                key: value for key, value in self._entities.items() if value.is_sp()
            }
        return {}


# Keep the exception type identical across ``mdstore`` and ``s_utils`` without
# creating an import cycle during configuration loading.
from .s_utils import UnknownSystemEntity  # noqa: I001 - intentional late import


__all__ = ["MetaDataMDX", "MetadataStore", "SourceNotFound"]
