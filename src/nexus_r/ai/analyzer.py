"""Hypothesis analyzer.

Coordinates hypothesis generation. In STEP 25A the only backend is
the template analyzer (offline). STEP 25B will add an AI backend that
can be selected via configuration; it will still fall back to the
template analyzer whenever the AI is unavailable.
"""

from __future__ import annotations

from typing import Any

from nexus_r.ai.model import Hypothesis
from nexus_r.ai.template_analyzer import TemplateAnalyzer


class HypothesisAnalyzer:
    """Produces hypotheses from a NEXUS-R report."""

    def __init__(self, backend: object | None = None) -> None:
        self.backend = backend if backend is not None else TemplateAnalyzer()

    def analyze(self, report: dict[str, Any]) -> list[Hypothesis]:
        results: list[Hypothesis] = []
        try:
            produced = self.backend.analyze(report)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - never crash the scan
            produced = TemplateAnalyzer().analyze(report)
        for h in produced:
            if isinstance(h, Hypothesis):
                results.append(h)
        return results
