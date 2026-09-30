"""Unit tests for DockerGroupSocketCorrelation."""

from __future__ import annotations

from nexus_r.analysis import Confidence, Finding, Severity
from nexus_r.analysis.correlation.rules.docker_group_socket import (
    DockerGroupSocketCorrelation,
)
from nexus_r.evidence import EvidenceStore


def _group_finding() -> Finding:
    return Finding(
        id="F-0001",
        rule_id="NEXUS-GROUP-001",
        title="Group 'docker' has members: rendy",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
    )


def _socket_finding() -> Finding:
    return Finding(
        id="F-0002",
        rule_id="NEXUS-DOCKER-001",
        title="Docker socket present: /var/run/docker.sock",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
    )


def test_empty_findings() -> None:
    result = DockerGroupSocketCorrelation().evaluate([], EvidenceStore())
    assert result == []


def test_only_group() -> None:
    findings = [_group_finding()]
    result = DockerGroupSocketCorrelation().evaluate(findings, EvidenceStore())
    assert result == []


def test_only_socket() -> None:
    findings = [_socket_finding()]
    result = DockerGroupSocketCorrelation().evaluate(findings, EvidenceStore())
    assert result == []


def test_both_produces_attack_path() -> None:
    findings = [_group_finding(), _socket_finding()]
    result = DockerGroupSocketCorrelation().evaluate(findings, EvidenceStore())
    assert len(result) == 1
    r = result[0]
    assert r.rule_id == "NEXUS-CORR-DOCKER-001"
    assert r.severity == Severity.CRITICAL
    assert r.confidence == Confidence.HIGH
    assert set(r.finding_ids) == {"F-0001", "F-0002"}
    assert r.entry_point == "user"
    assert r.target == "root"
    assert "docker" in r.narrative.lower()


def test_ignores_non_docker_group() -> None:
    g = Finding(
        id="F-0001",
        rule_id="NEXUS-GROUP-001",
        title="Group 'sudo' has members: rendy",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
    )
    result = DockerGroupSocketCorrelation().evaluate(
        [g, _socket_finding()], EvidenceStore()
    )
    assert result == []


def test_ignores_containerd_only() -> None:
    """Correlation requires a docker.sock finding, not just containerd."""
    s = Finding(
        id="F-0002",
        rule_id="NEXUS-DOCKER-001",
        title="Docker socket present: /run/containerd/containerd.sock",
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
    )
    result = DockerGroupSocketCorrelation().evaluate(
        [_group_finding(), s], EvidenceStore()
    )
    assert result == []
