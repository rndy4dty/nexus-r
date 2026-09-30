"""Unit tests for WritableCollector."""

from __future__ import annotations

from nexus_r.collectors.writable import WritableCollector
from nexus_r.evidence import EvidenceType


def test_writable_collector_runs() -> None:
    items = WritableCollector().collect()
    assert isinstance(items, list)


def test_writable_collector_types() -> None:
    items = WritableCollector().collect()
    for item in items:
        assert item.type == EvidenceType.WRITABLE
        assert item.source == "writable"


def test_writable_collector_ids_unique() -> None:
    items = WritableCollector().collect()
    ids = [item.id for item in items]
    assert len(ids) == len(set(ids))
    for i in ids:
        assert i.startswith("wrt-")


def test_writable_collector_data_shape() -> None:
    items = WritableCollector().collect()
    for item in items:
        for key in (
            "path",
            "mode",
            "owner_uid",
            "group_gid",
            "world_writable",
            "group_writable",
            "owner_writable",
            "is_dir",
        ):
            assert key in item.data
