"""Collector registry."""

from __future__ import annotations

from nexus_r.collectors.base import BaseCollector
from nexus_r.collectors.capabilities import CapabilitiesCollector
from nexus_r.collectors.cron import CronCollector
from nexus_r.collectors.environment import EnvironmentCollector
from nexus_r.collectors.sudo import SudoCollector
from nexus_r.collectors.suid import SuidCollector
from nexus_r.collectors.system import SystemCollector
from nexus_r.collectors.users import UsersCollector
from nexus_r.collectors.writable import WritableCollector

COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
    SystemCollector.name: SystemCollector,
    UsersCollector.name: UsersCollector,
    SudoCollector.name: SudoCollector,
    SuidCollector.name: SuidCollector,
    CapabilitiesCollector.name: CapabilitiesCollector,
    CronCollector.name: CronCollector,
    WritableCollector.name: WritableCollector,
    EnvironmentCollector.name: EnvironmentCollector,
}

__all__ = [
    "BaseCollector",
    "COLLECTOR_REGISTRY",
    "CapabilitiesCollector",
    "CronCollector",
    "EnvironmentCollector",
    "SudoCollector",
    "SystemCollector",
    "SuidCollector",
    "UsersCollector",
    "WritableCollector",
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
