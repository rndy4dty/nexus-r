"""Unit tests for WritableSystemdUnitRule."""

from __future__ import annotations

from nexus_r.analysis import Confidence, Severity
from nexus_r.analysis.rules.writable_service_binary import WritableSystemdUnitRule
from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def _unit(path: str, *, world: bool = False, group: bool = False) -> Evidence:
    return Evidence(
        id=f"sysd-{abs(hash(path)) % 10000:04d}",
        type=EvidenceType.SYSTEMD,
        source="systemd",
        data={
            "path": path,
            "mode": "0o666" if world else "0o644",
            "owner_uid": 0,
            "group_gid": 0,
            "world_writable": world,
            "group_writable": group,
            "owner_writable": True,
        },
    )


def test_empty() -> None:
    assert WritableSystemdUnitRule().evaluate(EvidenceStore()) == []


def test_world_writable_unit() -> None:
    store = EvidenceStore()
    store.add(_unit("/etc/systemd/system/evil.service", world=True))
    results = WritableSystemdUnitRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.HIGH
    assert results[0].confidence == Confidence.HIGH


def test_group_writable_unit() -> None:
    store = EvidenceStore()
    store.add(_unit("/etc/systemd/system/foo.service", group=True))
    results = WritableSystemdUnitRule().evaluate(store)
    assert len(results) == 1


def test_safe_unit_ignored() -> None:
    store = EvidenceStore()
    store.add(_unit("/lib/systemd/system/nginx.service"))
    assert WritableSystemdUnitRule().evaluate(store) == []
