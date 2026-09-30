"""Unit tests for SshKeyLateralCorrelation."""

from __future__ import annotations

from nexus_r.analysis import Confidence, Finding, Severity
from nexus_r.analysis.correlation.path import AttackPathStatus
from nexus_r.analysis.correlation.rules.ssh_key_lateral import (
    SshKeyLateralCorrelation,
)
from nexus_r.evidence import EvidenceStore


def _ssh_finding(fid: str = "F-0001") -> Finding:
    return Finding(
        id=fid,
        rule_id="NEXUS-SSH-001",
        title="Private SSH key readable: /home/rendy/.ssh/id_ed25519",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
    )


def test_empty() -> None:
    assert SshKeyLateralCorrelation().evaluate([], EvidenceStore()) == []


def test_ssh_key_produces_path() -> None:
    findings = [_ssh_finding()]
    result = SshKeyLateralCorrelation().evaluate(findings, EvidenceStore())
    assert len(result) == 1
    r = result[0]
    assert r.rule_id == "NEXUS-CORR-SSH-001"
    assert r.severity == Severity.HIGH
    assert r.confidence == Confidence.MEDIUM
    assert r.entry_point == "current-host"
    assert r.target == "remote-host"
    assert r.status == AttackPathStatus.HYPOTHESIS
    assert r.finding_ids == ["F-0001"]


def test_unrelated_finding_ignored() -> None:
    f = Finding(
        id="F-0001",
        rule_id="NEXUS-SUID-001",
        title="SUID sudo — known GTFOBins privesc vector",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
    )
    assert SshKeyLateralCorrelation().evaluate([f], EvidenceStore()) == []


def test_other_ssh_finding_ignored() -> None:
    """Only NEXUS-SSH-001 for private keys is considered."""
    f = Finding(
        id="F-0001",
        rule_id="NEXUS-SSH-999",
        title="SSH private key readable",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
    )
    assert SshKeyLateralCorrelation().evaluate([f], EvidenceStore()) == []
