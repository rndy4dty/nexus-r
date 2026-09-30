"""Collector registry."""

from __future__ import annotations

from nexus_r.collectors.base import BaseCollector
from nexus_r.collectors.suid import SuidCollector

COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
    SuidCollector.name: SuidCollector,
}

__all__ = [
    "BaseCollector",
    "COLLECTOR_REGISTRY",
    "SuidCollector",
    "get_collectors",
]


def get_collectors(names: tuple[str, ...] = ()) -> list[BaseCollector]:
    """Return collector instances. Empty names means all registered."""
    if not names:
        return [cls() for cls in COLLECTOR_REGISTRY.values()]

    result: list[BaseCollector] = []
    for name in names:
        if name not in COLLECTOR_REGISTRY:
            raise ValueError(f"unknown collector: {name}")
        result.append(COLLECTOR_REGISTRY[name]())
    return result
