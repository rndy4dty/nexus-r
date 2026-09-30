"""Unit tests for DangerousGroupsRule."""

from __future__ import annotations

from nexus_r.analysis import Confidence, Severity
from nexus_r.analysis.rules.dangerous_groups import DangerousGroupsRule
from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def _group(name: str, members: list[str]) -> Evidence:
    return Evidence(
        id=f"grp-{abs(hash(name)) % 10000:04d}",
        type=EvidenceType.GROUP,
        source="users",
        data={"name": name, "gid": 1000, "members": members},
    )


def test_empty_store() -> None:
    assert DangerousGroupsRule().evaluate(EvidenceStore()) == []


def test_docker_group() -> None:
    store = EvidenceStore()
    store.add(_group("docker", ["rendy"]))
    results = DangerousGroupsRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.CRITICAL
    assert "rendy" in results[0].title


def test_sudo_group() -> None:
    store = EvidenceStore()
    store.add(_group("sudo", ["alice", "bob"]))
    results = DangerousGroupsRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.HIGH


def test_lxd_critical() -> None:
    store = EvidenceStore()
    store.add(_group("lxd", ["carol"]))
    results = DangerousGroupsRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.CRITICAL


def test_safe_group_ignored() -> None:
    store = EvidenceStore()
    store.add(_group("www-data", ["alice"]))
    assert DangerousGroupsRule().evaluate(store) == []


def test_empty_members_ignored() -> None:
    store = EvidenceStore()
    store.add(_group("docker", []))
    assert DangerousGroupsRule().evaluate(store) == []


def test_confidence_medium() -> None:
    store = EvidenceStore()
    store.add(_group("adm", ["sysadmin"]))
    results = DangerousGroupsRule().evaluate(store)
    assert len(results) == 1
    assert results[0].confidence == Confidence.MEDIUM
