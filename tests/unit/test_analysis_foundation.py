"""Unit tests for analysis foundation (Finding, Rule, RuleEngine)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nexus_r.analysis import Confidence, Finding, RuleEngine, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore


def test_finding_construction() -> None:
    f = Finding(
        id="F-0001",
        rule_id="TEST-001",
        title="Test finding",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
    )
    assert f.id == "F-0001"
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.MEDIUM
    assert f.evidence_ids == ()


def test_finding_is_frozen() -> None:
    f = Finding(
        id="F-0001",
        rule_id="TEST-001",
        title="Test",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
    )
    with pytest.raises(ValidationError):
        f.id = "F-9999"  # type: ignore[misc]


def test_finding_to_json_dict() -> None:
    f = Finding(
        id="F-0001",
        rule_id="TEST-001",
        title="Test",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    )
    payload = f.to_json_dict()
    assert payload["severity"] == "critical"
    assert payload["confidence"] == "high"
    assert isinstance(payload["created_at"], str)


def test_rule_engine_with_no_rules() -> None:
    store = EvidenceStore()
    engine = RuleEngine(rules=[])
    assert engine.evaluate(store) == []


def test_rule_engine_assigns_ids() -> None:
    class DummyRule(Rule):
        id = "DUMMY-001"
        title = "Dummy"

        def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
            return [
                RuleResult(
                    rule_id=self.id,
                    title="dummy finding",
                    description="",
                    category="test",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                )
            ]

    engine = RuleEngine(rules=[DummyRule()])
    findings = engine.evaluate(EvidenceStore())
    assert len(findings) == 1
    assert findings[0].id == "F-0001"
    assert findings[0].rule_id == "DUMMY-001"


def test_rule_engine_dedup() -> None:
    class DupRule(Rule):
        id = "DUP-001"

        def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
            return [
                RuleResult(
                    rule_id=self.id,
                    title="same",
                    description="",
                    category="test",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    evidence_ids=["E-0001"],
                ),
                RuleResult(
                    rule_id=self.id,
                    title="same",
                    description="",
                    category="test",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    evidence_ids=["E-0001"],
                ),
            ]

    engine = RuleEngine(rules=[DupRule()])
    findings = engine.evaluate(EvidenceStore())
    assert len(findings) == 1
