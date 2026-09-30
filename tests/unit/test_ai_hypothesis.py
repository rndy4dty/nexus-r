"""Unit tests for the AI hypothesis layer (template mode)."""

from __future__ import annotations

from nexus_r.ai import (
    Hypothesis,
    HypothesisAnalyzer,
    HypothesisMode,
    HypothesisStatus,
    TemplateAnalyzer,
)
from nexus_r.analysis import Confidence, Severity


def _report_with_findings() -> dict:
    return {
        "findings": [
            {
                "id": "F-0001",
                "rule_id": "NEXUS-SUID-001",
                "category": "privilege-escalation",
                "severity": "high",
                "confidence": "medium",
            },
            {
                "id": "F-0002",
                "rule_id": "NEXUS-SUDO-001",
                "category": "privilege-escalation",
                "severity": "high",
                "confidence": "high",
            },
            {
                "id": "F-0003",
                "rule_id": "NEXUS-SSH-001",
                "category": "credential-exposure",
                "severity": "high",
                "confidence": "medium",
            },
        ],
    }


def test_hypothesis_construction() -> None:
    h = Hypothesis(id="H-0001", title="test")
    assert h.mode == HypothesisMode.TEMPLATE
    assert h.status == HypothesisStatus.NEEDS_REVIEW
    assert h.finding_ids == ()


def test_template_analyzer_empty_report() -> None:
    assert TemplateAnalyzer().analyze({}) == []


def test_template_analyzer_groups_by_category() -> None:
    report = _report_with_findings()
    result = TemplateAnalyzer().analyze(report)
    categories = {h.title.split(":")[0] for h in result}
    assert "privilege-escalation" in categories
    assert "credential-exposure" in categories


def test_template_analyzer_finding_ids_referenced() -> None:
    report = _report_with_findings()
    result = TemplateAnalyzer().analyze(report)
    all_ids = set()
    for h in result:
        all_ids.update(h.finding_ids)
    assert all_ids == {"F-0001", "F-0002", "F-0003"}


def test_template_analyzer_severity_from_group() -> None:
    report = _report_with_findings()
    result = TemplateAnalyzer().analyze(report)
    privesc = next(
        h for h in result if h.title.startswith("privilege-escalation")
    )
    assert privesc.severity == Severity.HIGH
    assert privesc.confidence == Confidence.HIGH


def test_template_analyzer_has_validation_steps() -> None:
    report = _report_with_findings()
    result = TemplateAnalyzer().analyze(report)
    for h in result:
        assert len(h.validation_steps) >= 1


def test_template_analyzer_never_bypasses_human_validation() -> None:
    """Every hypothesis must be needs_review, never accepted/rejected."""
    report = _report_with_findings()
    result = TemplateAnalyzer().analyze(report)
    for h in result:
        assert h.status == HypothesisStatus.NEEDS_REVIEW


def test_hypothesis_analyzer_default_backend_is_template() -> None:
    analyzer = HypothesisAnalyzer()
    assert isinstance(analyzer.backend, TemplateAnalyzer)


def test_hypothesis_analyzer_returns_hypotheses() -> None:
    report = _report_with_findings()
    result = HypothesisAnalyzer().analyze(report)
    assert len(result) >= 2
    for h in result:
        assert isinstance(h, Hypothesis)


def test_hypothesis_analyzer_never_crashes() -> None:
    class Broken:
        def analyze(self, report):
            raise RuntimeError("simulated failure")

    # Broken backend should fall back to template
    analyzer = HypothesisAnalyzer(backend=Broken())
    report = _report_with_findings()
    result = analyzer.analyze(report)
    assert len(result) >= 2
