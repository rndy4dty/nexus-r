"""Unit tests for PackagesCollector."""

from __future__ import annotations

from nexus_r.collectors.packages import PackagesCollector
from nexus_r.evidence import EvidenceType


def test_packages_collector_runs() -> None:
    items = PackagesCollector().collect()
    assert isinstance(items, list)


def test_packages_collector_types() -> None:
    for item in PackagesCollector().collect():
        assert item.type == EvidenceType.PACKAGE
        assert item.source == "packages"
        assert item.id.startswith("pkg-")


def test_packages_collector_data_shape() -> None:
    for item in PackagesCollector().collect():
        assert "name" in item.data
        assert "version" in item.data


def test_packages_collector_ids_unique() -> None:
    items = PackagesCollector().collect()
    ids = [i.id for i in items]
    assert len(ids) == len(set(ids))
