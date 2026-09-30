"""Unit tests for DockerCollector."""

from __future__ import annotations

from nexus_r.collectors.docker import DockerCollector
from nexus_r.evidence import EvidenceType


def test_docker_collector_runs() -> None:
    items = DockerCollector().collect()
    # Always at least the process evidence
    assert len(items) >= 1


def test_docker_collector_types() -> None:
    items = DockerCollector().collect()
    for item in items:
        assert item.type == EvidenceType.DOCKER
        assert item.source == "docker"


def test_docker_collector_has_process() -> None:
    items = DockerCollector().collect()
    process_items = [i for i in items if i.data.get("kind") == "process"]
    assert len(process_items) == 1
    assert "in_container" in process_items[0].data
