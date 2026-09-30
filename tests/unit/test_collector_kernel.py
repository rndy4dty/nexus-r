"""Unit tests for KernelCollector."""

from __future__ import annotations

from nexus_r.collectors.kernel import KernelCollector
from nexus_r.evidence import EvidenceType


def test_kernel_collector_runs() -> None:
    items = KernelCollector().collect()
    assert isinstance(items, list)


def test_kernel_collector_types() -> None:
    items = KernelCollector().collect()
    for item in items:
        assert item.type == EvidenceType.SYSTEM
        assert item.source == "kernel"
        assert item.id.startswith("kern-")
