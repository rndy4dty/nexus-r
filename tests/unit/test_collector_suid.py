"""Unit tests for SuidCollector."""

from __future__ import annotations

from nexus_r.collectors.suid import SuidCollector
from nexus_r.evidence import EvidenceType


def test_suid_collector_runs() -> None:
    """Collector must run without raising."""
    collector = SuidCollector()
    items = collector.collect()
    assert isinstance(items, list)


def test_suid_collector_types() -> None:
    """Every returned item must be SUID or SGID."""
    collector = SuidCollector()
    items = collector.collect()
    for item in items:
        assert item.type in (EvidenceType.SUID, EvidenceType.SGID)


def test_suid_collector_ids_unique() -> None:
    """IDs must be unique within a single run."""
    collector = SuidCollector()
    items = collector.collect()
    ids = [item.id for item in items]
    assert len(ids) == len(set(ids))


def test_suid_collector_source() -> None:
    """Source must be 'suid'."""
    collector = SuidCollector()
    items = collector.collect()
    for item in items:
        assert item.source == "suid"


def test_suid_collector_data_shape() -> None:
    """Each item must carry path/mode/owner_uid/group_gid/size."""
    collector = SuidCollector()
    items = collector.collect()
    for item in items:
        for key in ("path", "mode", "owner_uid", "group_gid", "size"):
            assert key in item.data
