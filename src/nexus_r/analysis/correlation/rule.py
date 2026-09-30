"""Correlation rule base class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from nexus_r.analysis.correlation.path import AttackPathStatus
from nexus_r.analysis.finding import Confidence, Finding, Severity
from nexus_r.evidence import EvidenceStore


@dataclass
class CorrelationResult:
    """Intermediate result returned by a correlation rule."""

    rule_id: str
    title: str
    narrative: str
    category: str
    severity: Severity
    confidence: Confidence
    finding_ids: list[str] = field(default_factory=list)
    entry_point: str = ""
    target: str = "root"
    status: AttackPathStatus = AttackPathStatus.PLAUSIBLE
    validation_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


class CorrelationRule(ABC):
    """Abstract correlation rule.

    A correlation rule inspects findings (already produced by the rule
    engine) and may produce one or more CorrelationResults. It must
    not modify findings or evidence.
    """

    id: str = "corr-base"
    title: str = "Base correlation rule"

    @abstractmethod
    def evaluate(
        self, findings: list[Finding], store: EvidenceStore
    ) -> list[CorrelationResult]:
        raise NotImplementedError
