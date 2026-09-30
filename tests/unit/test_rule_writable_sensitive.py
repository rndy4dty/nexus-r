"""Unit tests for WritableSensitiveRule."""

from __future__ import annotations

from nexus_r.analysis import Confidence, Severity
from nexus_r.analysis.rules.writable_sensitive import WritableSensitiveRule
from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def _writable(path: str, *, world: bool = False, group: bool = False, mode: str = "0o644") -> Evidence:
    return Evidence(
        id=f"wrt-{abs(hash(path)) % 10000:04d}",
        type=EvidenceType.WRITABLE,
        source="writable",
        data={
            "path": path,
            "mode": mode,
            "owner_uid": 0,
            "group_gid": 0,
            "world_writable": world,
            "group_writable": group,
            "owner_writable": True,
            "is_dir": False,
        },
    )


def test_empty_store() -> None:
    assert WritableSensitiveRule().evaluate(EvidenceStore()) == []


def test_world_writable_etc_passwd() -> None:
    store = EvidenceStore()
    store.add(_writable("/etc/passwd", world=True, mode="0o666"))
    results = WritableSensitiveRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.CRITICAL
    assert results[0].confidence == Confidence.HIGH


def test_group_writable_sudoers() -> None:
    store = EvidenceStore()
    store.add(_writable("/etc/sudoers", group=True, mode="0o660"))
    results = WritableSensitiveRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.CRITICAL


def test_owner_only_not_flagged() -> None:
    store = EvidenceStore()
    store.add(_writable("/etc/passwd", mode="0o644"))
    assert WritableSensitiveRule().evaluate(store) == []


def test_unknown_path_ignored() -> None:
    store = EvidenceStore()
    store.add(_writable("/opt/somefile", world=True, mode="0o666"))
    assert WritableSensitiveRule().evaluate(store) == []
