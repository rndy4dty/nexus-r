"""Rule base class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.evidence import EvidenceStore


@dataclass
class RuleResult:
    """Intermediate result returned by a rule before ID assignment."""

    rule_id: str
    title: str
    description: str
    category: str
    severity: Severity
    confidence: Confidence
    evidence_ids: list[str] = field(default_factory=list)
    validation_steps: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


class Rule(ABC):
    """Abstract rule.

    A Rule inspects the EvidenceStore and produces zero or more RuleResults.
    It must not mutate evidence or call external tools.
    """

    id: str = "rule-base"
    title: str = "Base rule"
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW

    @abstractmethod
    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        raise NotImplementedError
