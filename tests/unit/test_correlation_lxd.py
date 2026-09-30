"""Unit tests for LxdGroupCorrelation."""

from __future__ import annotations

from nexus_r.analysis import Confidence, Finding, Severity
from nexus_r.analysis.correlation.rules.lxd_group import LxdGroupCorrelation
from nexus_r.evidence import EvidenceStore


def _group_finding(name: str, fid: str = "F-0001") -> Finding:
    return Finding(
        id=fid,
        rule_id="NEXUS-GROUP-001",
        title=f"Group '{name}' has members: rendy",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
    )


def test_empty() -> None:
    assert LxdGroupCorrelation().evaluate([], EvidenceStore()) == []


def test_lxd_group_produces_path() -> None:
    findings = [_group_finding("lxd")]
    result = LxdGroupCorrelation().evaluate(findings, EvidenceStore())
    assert len(result) == 1
    r = result[0]
    assert r.rule_id == "NEXUS-CORR-LXD-001"
    assert r.severity == Severity.CRITICAL
    assert r.confidence == Confidence.HIGH
    assert r.finding_ids == ["F-0001"]
    assert r.entry_point == "user"
    assert r.target == "root"


def test_lxc_group_produces_path() -> None:
    findings = [_group_finding("lxc")]
    result = LxdGroupCorrelation().evaluate(findings, EvidenceStore())
    assert len(result) == 1


def test_docker_group_ignored() -> None:
    findings = [_group_finding("docker")]
    assert LxdGroupCorrelation().evaluate(findings, EvidenceStore()) == []


def test_sudo_group_ignored() -> None:
    findings = [_group_finding("sudo")]
    assert LxdGroupCorrelation().evaluate(findings, EvidenceStore()) == []


def test_non_group_finding_ignored() -> None:
    f = Finding(
        id="F-0001",
        rule_id="NEXUS-DOCKER-001",
        title="Docker socket present: /var/run/docker.sock",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
    )
    assert LxdGroupCorrelation().evaluate([f], EvidenceStore()) == []
