"""Unit tests for AI backends (parser + fallback, no real LLM)."""

from __future__ import annotations

from nexus_r.ai import (
    Hypothesis,
    HypothesisAnalyzer,
    HypothesisMode,
    HypothesisStatus,
    OllamaAnalyzer,
    OpenAIAnalyzer,
)
from nexus_r.ai.backends import _parse_hypotheses


def _report() -> dict:
    return {
        "findings": [
            {"id": "F-0001", "rule_id": "NEXUS-SUID-001",
             "title": "SUID find", "severity": "high",
             "confidence": "medium", "category": "privilege-escalation"},
            {"id": "F-0002", "rule_id": "NEXUS-SSH-001",
             "title": "Readable SSH key", "severity": "high",
             "confidence": "medium", "category": "credential-exposure"},
        ]
    }


def test_parse_hypotheses_basic() -> None:
    raw = """[
      {"title": "SUID find path", "narrative": "Check GTFOBins.",
       "severity": "high", "confidence": "medium",
       "finding_ids": ["F-0001"],
       "validation_steps": ["ls -la /usr/bin/find"]}
    ]"""
    index = {"F-0001": {}, "F-0002": {}}
    result = _parse_hypotheses(raw, index, HypothesisMode.OLLAMA, "llama3.2")
    assert len(result) == 1
    h = result[0]
    assert h.finding_ids == ("F-0001",)
    assert h.status == HypothesisStatus.NEEDS_REVIEW
    assert h.mode == HypothesisMode.OLLAMA
    assert h.model == "llama3.2"


def test_parse_hypotheses_drops_unknown_finding_ids() -> None:
    raw = """[{"title": "x", "finding_ids": ["F-9999"],
              "severity": "high", "confidence": "low"}]"""
    result = _parse_hypotheses(raw, {"F-0001": {}}, HypothesisMode.OLLAMA, "m")
    assert result == []


def test_parse_hypotheses_wrapped_in_prose() -> None:
    raw = ('Sure:\n[{"title":"x","finding_ids":["F-0001"],'
           '"severity":"high","confidence":"low"}]\nDone.')
    result = _parse_hypotheses(raw, {"F-0001": {}}, HypothesisMode.OPENAI, "gpt")
    assert len(result) == 1


def test_parse_hypotheses_empty() -> None:
    assert _parse_hypotheses("no json", {"F-0001": {}}, HypothesisMode.OLLAMA, "m") == []
    assert _parse_hypotheses("[]", {"F-0001": {}}, HypothesisMode.OLLAMA, "m") == []


def test_parse_hypotheses_invalid_severity_defaults_info() -> None:
    raw = '[{"title":"x","finding_ids":["F-0001"],"severity":"nonsense","confidence":"low"}]'
    result = _parse_hypotheses(raw, {"F-0001": {}}, HypothesisMode.OLLAMA, "m")
    assert len(result) == 1
    assert result[0].severity.value == "info"


def test_ollama_is_available_returns_bool() -> None:
    backend = OllamaAnalyzer(url="http://127.0.0.1:1")
    assert backend.is_available() is False


def test_openai_is_available_requires_key() -> None:
    assert OpenAIAnalyzer(api_key="").is_available() is False
    assert OpenAIAnalyzer(api_key="sk-x").is_available() is True


def test_analyzer_falls_back_to_template_on_backend_error() -> None:
    class Broken:
        def analyze(self, report):
            raise RuntimeError("simulated")

    report = _report()
    result = HypothesisAnalyzer(backend=Broken()).analyze(report)
    assert len(result) >= 1
    for h in result:
        assert isinstance(h, Hypothesis)
        assert h.mode == HypothesisMode.TEMPLATE


def test_analyzer_falls_back_when_backend_returns_empty() -> None:
    class Empty:
        def analyze(self, report):
            return []

    result = HypothesisAnalyzer(backend=Empty()).analyze(_report())
    assert len(result) >= 1
    for h in result:
        assert h.mode == HypothesisMode.TEMPLATE


def test_analyzer_uses_backend_when_successful() -> None:
    class Fixed:
        def analyze(self, report):
            return [Hypothesis(id="H-AI-0001", title="fixed",
                               mode=HypothesisMode.OLLAMA, model="llama3.2")]

    result = HypothesisAnalyzer(backend=Fixed()).analyze(_report())
    assert len(result) == 1
    assert result[0].mode == HypothesisMode.OLLAMA


def test_default_analyzer_is_template() -> None:
    result = HypothesisAnalyzer().analyze(_report())
    for h in result:
        assert h.mode == HypothesisMode.TEMPLATE
