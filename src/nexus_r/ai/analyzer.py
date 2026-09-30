"""Hypothesis analyzer.

Coordinates hypothesis generation. By default the template analyzer
is used (offline). When an AI backend is provided and available, it is
preferred; otherwise the analyzer silently falls back to the template
so a scan never fails because of an LLM outage.
"""

from __future__ import annotations

from typing import Any, Protocol

from nexus_r.ai.model import Hypothesis
from nexus_r.ai.template_analyzer import TemplateAnalyzer


class _Backend(Protocol):
    def analyze(self, report: dict[str, Any]) -> list[Hypothesis]: ...


class HypothesisAnalyzer:
    """Produces hypotheses from a NEXUS-R report."""

    def __init__(self, backend: _Backend | None = None) -> None:
        self.backend = backend if backend is not None else TemplateAnalyzer()

    def analyze(self, report: dict[str, Any]) -> list[Hypothesis]:
        results: list[Hypothesis] = []
        backend = self.backend
        try:
            produced = backend.analyze(report)
        except Exception:  # noqa: BLE001
            produced = TemplateAnalyzer().analyze(report)
            backend = TemplateAnalyzer()

        if not produced and not isinstance(backend, TemplateAnalyzer):
            produced = TemplateAnalyzer().analyze(report)

        for h in produced:
            if isinstance(h, Hypothesis):
                results.append(h)
        return results
