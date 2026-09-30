"""Unit tests for SudoCollector."""

from __future__ import annotations

from nexus_r.collectors.sudo import SudoCollector
from nexus_r.evidence import EvidenceType


def test_sudo_collector_runs() -> None:
    items = SudoCollector().collect()
    assert isinstance(items, list)


def test_sudo_collector_types() -> None:
    items = SudoCollector().collect()
    for item in items:
        assert item.type == EvidenceType.SUDO
        assert item.source == "sudo"


def test_sudo_collector_ids_unique() -> None:
    items = SudoCollector().collect()
    ids = [item.id for item in items]
    assert len(ids) == len(set(ids))


def test_sudo_collector_data_shape() -> None:
    items = SudoCollector().collect()
    for item in items:
        assert "path" in item.data
        assert "readable" in item.data
