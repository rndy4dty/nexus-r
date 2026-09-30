"""Unit tests for correlation foundation (AttackPath, CorrelationEngine)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nexus_r.analysis import (
    AttackPath,
    AttackPathStatus,
    Confidence,
    CorrelationEngine,
    Finding,
    Severity,
)
from nexus_r.analysis.correlation.rule import CorrelationResult, CorrelationRule
from nexus_r.evidence import EvidenceStore


def _finding(fid: str = "F-0001", rule_id: str = "TEST-001") -> Finding:
    return Finding(
        id=fid,
        rule_id=rule_id,
        title="test finding",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
    )


def test_attack_path_construction() -> None:
    p = AttackPath(
        id="AP-0001",
        rule_id="CORR-001",
        title="user -> root via docker",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    )
    assert p.id == "AP-0001"
    assert p.status == AttackPathStatus.PLAUSIBLE
    assert p.target == "root"
    assert p.finding_ids == ()


def test_attack_path_is_frozen() -> None:
    p = AttackPath(
        id="AP-0001",
        rule_id="CORR-001",
        title="t",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
    )
    with pytest.raises(ValidationError):
        p.id = "AP-9999"  # type: ignore[misc]


def test_attack_path_to_json_dict() -> None:
    p = AttackPath(
        id="AP-0001",
        rule_id="CORR-001",
        title="t",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    )
    payload = p.to_json_dict()
    assert payload["severity"] == "critical"
    assert payload["confidence"] == "high"
    assert payload["status"] == "plausible"
    assert isinstance(payload["created_at"], str)


def test_correlation_engine_with_no_rules() -> None:
    engine = CorrelationEngine(rules=[])
    findings = [_finding()]
    store = EvidenceStore()
    assert engine.evaluate(findings, store) == []


def test_correlation_engine_assigns_ids() -> None:
    class DummyCorr(CorrelationRule):
        id = "DUMMY-CORR-001"

        def evaluate(self, findings, store):
            return [
                CorrelationResult(
                    rule_id=self.id,
                    title="dummy path",
                    narrative="",
                    category="test",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    finding_ids=[findings[0].id],
                )
            ]

    engine = CorrelationEngine(rules=[DummyCorr()])
    findings = [_finding()]
    paths = engine.evaluate(findings, EvidenceStore())
    assert len(paths) == 1
    assert paths[0].id == "AP-0001"
    assert paths[0].rule_id == "DUMMY-CORR-001"


def test_correlation_engine_dedup() -> None:
    class DupCorr(CorrelationRule):
        id = "DUP-CORR-001"

        def evaluate(self, findings, store):
            return [
                CorrelationResult(
                    rule_id=self.id,
                    title="same",
                    narrative="",
                    category="test",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    finding_ids=["F-0001"],
                ),
                CorrelationResult(
                    rule_id=self.id,
                    title="same",
                    narrative="",
                    category="test",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    finding_ids=["F-0001"],
                ),
            ]

    engine = CorrelationEngine(rules=[DupCorr()])
    paths = engine.evaluate([_finding()], EvidenceStore())
    assert len(paths) == 1
