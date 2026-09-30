"""AI hypothesis layer.

The AI layer never produces findings. It only produces hypotheses that
comment on existing findings and attack paths. Every hypothesis always
requires human validation (ADR-001 §3.7).
"""

from nexus_r.ai.analyzer import HypothesisAnalyzer
from nexus_r.ai.model import Hypothesis, HypothesisMode, HypothesisStatus
from nexus_r.ai.template_analyzer import TemplateAnalyzer

__all__ = [
    "Hypothesis",
    "HypothesisAnalyzer",
    "HypothesisMode",
    "HypothesisStatus",
    "TemplateAnalyzer",
]
