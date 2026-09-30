"""Unit tests for CronCollector."""

from __future__ import annotations

from nexus_r.collectors.cron import CronCollector
from nexus_r.evidence import EvidenceType


def test_cron_collector_runs() -> None:
    items = CronCollector().collect()
    assert isinstance(items, list)


def test_cron_collector_types() -> None:
    items = CronCollector().collect()
    for item in items:
        assert item.type == EvidenceType.CRON
        assert item.source == "cron"


def test_cron_collector_ids_unique() -> None:
    items = CronCollector().collect()
    ids = [item.id for item in items]
    assert len(ids) == len(set(ids))
    for i in ids:
        assert i.startswith("cron-")


def test_cron_collector_data_shape() -> None:
    items = CronCollector().collect()
    for item in items:
        assert "path" in item.data
        assert "kind" in item.data
