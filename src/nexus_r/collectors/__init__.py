"""Collector registry."""

from __future__ import annotations

from nexus_r.collectors.base import BaseCollector
from nexus_r.collectors.capabilities import CapabilitiesCollector
from nexus_r.collectors.sudo import SudoCollector
from nexus_r.collectors.suid import SuidCollector
from nexus_r.collectors.system import SystemCollector
from nexus_r.collectors.users import UsersCollector

COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
    SystemCollector.name: SystemCollector,
    UsersCollector.name: UsersCollector,
    SudoCollector.name: SudoCollector,
    SuidCollector.name: SuidCollector,
    CapabilitiesCollector.name: CapabilitiesCollector,
}

__all__ = [
    "BaseCollector",
    "COLLECTOR_REGISTRY",
    "CapabilitiesCollector",
    "SudoCollector",
    "SystemCollector",
    "SuidCollector",
    "UsersCollector",
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
