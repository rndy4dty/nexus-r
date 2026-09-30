"""Unit tests for EnvironmentCollector."""

from __future__ import annotations

from pathlib import Path

from nexus_r.collectors.environment import EnvironmentCollector
from nexus_r.evidence import EvidenceType


def test_environment_collector_runs() -> None:
    items = EnvironmentCollector().collect()
    assert len(items) >= 1


def test_environment_collector_types() -> None:
    items = EnvironmentCollector().collect()
    for item in items:
        assert item.type == EvidenceType.OTHER
        assert item.source == "environment"


def test_environment_collector_has_env_item() -> None:
    items = EnvironmentCollector().collect()
    env_items = [i for i in items if i.data.get("kind") == "env"]
    assert len(env_items) == 1
    assert "variables" in env_items[0].data


def test_environment_collector_path_entries() -> None:
    items = EnvironmentCollector().collect()
    path_items = [i for i in items if i.data.get("kind") == "path_entry"]
    # On any normal Linux system, PATH contains at least /usr/bin
    assert len(path_items) >= 1
    for item in path_items:
        assert item.data["is_dir"] is True
        assert "world_writable" in item.data


def test_environment_collector_redacts_secrets(monkeypatch) -> None:
    monkeypatch.setenv("MY_SECRET_TOKEN", "super-secret-value")
    items = EnvironmentCollector().collect()
    env_items = [i for i in items if i.data.get("kind") == "env"]
    assert env_items
    variables = env_items[0].data["variables"]
    assert variables.get("MY_SECRET_TOKEN") == "<redacted>"
