"""Unit tests for SuidGtfobinsRule."""

from __future__ import annotations

from nexus_r.analysis import Confidence, Severity
from nexus_r.analysis.rules.suid_gtfobins import SuidGtfobinsRule
from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def _store_with_paths(paths: list[str]) -> EvidenceStore:
    store = EvidenceStore()
    for i, p in enumerate(paths, start=1):
        store.add(
            Evidence(
                id=f"suid-{i:04d}",
                type=EvidenceType.SUID,
                source="suid",
                data={"path": p, "mode": "0o4755", "owner_uid": 0, "group_gid": 0, "size": 0},
            )
        )
    return store


def test_no_suid_evidence() -> None:
    rule = SuidGtfobinsRule()
    results = rule.evaluate(EvidenceStore())
    assert results == []


def test_non_gtfobins_suid_ignored() -> None:
    store = _store_with_paths(["/usr/bin/some-random-tool", "/opt/foo"])
    results = SuidGtfobinsRule().evaluate(store)
    assert results == []


def test_gtfobins_suid_detected() -> None:
    store = _store_with_paths(["/usr/bin/vim"])
    results = SuidGtfobinsRule().evaluate(store)
    assert len(results) == 1
    r = results[0]
    assert r.rule_id == "NEXUS-SUID-001"
    assert r.severity == Severity.HIGH
    assert r.confidence == Confidence.MEDIUM
    assert r.evidence_ids == ["suid-0001"]
    assert any("gtfobins" in ref.lower() for ref in r.references)


def test_gtfobins_by_basename_only() -> None:
    """Binary name is matched, not full path."""
    store = _store_with_paths(["/some/weird/path/bash"])
    results = SuidGtfobinsRule().evaluate(store)
    assert len(results) == 1
    assert "bash" in results[0].title


def test_multiple_matches() -> None:
    store = _store_with_paths(["/usr/bin/vim", "/usr/bin/find", "/usr/bin/not-a-real-bin"])
    results = SuidGtfobinsRule().evaluate(store)
    assert len(results) == 2
