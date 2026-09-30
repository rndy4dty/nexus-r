"""Unit tests for ServicesCollector and SystemdCollector."""

from __future__ import annotations

from nexus_r.collectors.services import ServicesCollector
from nexus_r.collectors.systemd import SystemdCollector
from nexus_r.evidence import EvidenceType


def test_services_collector_runs() -> None:
    items = ServicesCollector().collect()
    assert isinstance(items, list)
    for item in items:
        assert item.type == EvidenceType.SERVICE
        assert item.source == "services"


def test_services_collector_ids_unique() -> None:
    items = ServicesCollector().collect()
    ids = [i.id for i in items]
    assert len(ids) == len(set(ids))


def test_systemd_collector_runs() -> None:
    items = SystemdCollector().collect()
    assert isinstance(items, list)


def test_systemd_collector_types() -> None:
    items = SystemdCollector().collect()
    for item in items:
        assert item.type == EvidenceType.SYSTEMD
        assert item.source == "systemd"
        assert item.id.startswith("sysd-")


def test_systemd_collector_data_shape() -> None:
    items = SystemdCollector().collect()
    for item in items:
        for key in (
            "path", "mode", "owner_uid", "group_gid",
            "world_writable", "group_writable", "owner_writable",
        ):
            assert key in item.data
