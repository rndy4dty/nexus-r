"""Correlation layer: attack paths and correlation rules."""

from nexus_r.analysis.correlation.engine import CorrelationEngine
from nexus_r.analysis.correlation.path import AttackPath, AttackPathStatus
from nexus_r.analysis.correlation.rule import CorrelationResult, CorrelationRule

__all__ = [
    "AttackPath",
    "AttackPathStatus",
    "CorrelationEngine",
    "CorrelationResult",
    "CorrelationRule",
]
