"""Unit tests for SystemCollector."""

from __future__ import annotations

from nexus_r.collectors.system import SystemCollector
from nexus_r.evidence import EvidenceType


def test_system_collector_runs() -> None:
    items = SystemCollector().collect()
    assert len(items) >= 1


def test_system_collector_types() -> None:
    items = SystemCollector().collect()
    for item in items:
        assert item.type == EvidenceType.SYSTEM
        assert item.source == "system"


def test_system_collector_has_kernel() -> None:
    items = SystemCollector().collect()
    assert any("kernel_release" in i.data for i in items)


def test_system_collector_has_os_release() -> None:
    items = SystemCollector().collect()
    os_items = [i for i in items if "os_release" in i.data]
    if os_items:
        assert isinstance(os_items[0].data["os_release"], dict)


def test_system_collector_ids_unique() -> None:
    items = SystemCollector().collect()
    ids = [i.id for i in items]
    assert len(ids) == len(set(ids))
    for i in ids:
        assert i.startswith("sys-")
