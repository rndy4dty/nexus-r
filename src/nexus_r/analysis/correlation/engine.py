"""Correlation engine.

Runs registered correlation rules against the findings produced by the
rule engine, and produces deduplicated AttackPaths.
"""

from __future__ import annotations

from nexus_r.analysis.correlation.path import AttackPath
from nexus_r.analysis.correlation.rule import CorrelationResult, CorrelationRule
from nexus_r.analysis.correlation.rules import get_correlation_rules
from nexus_r.analysis.finding import Finding
from nexus_r.evidence import EvidenceStore


class CorrelationEngine:
    """Executes correlation rules and produces attack paths."""

    def __init__(self, rules: list[CorrelationRule] | None = None) -> None:
        self.rules = (
            rules if rules is not None else get_correlation_rules()
        )
        self._counter = 0

    def evaluate(
        self, findings: list[Finding], store: EvidenceStore
    ) -> list[AttackPath]:
        paths: list[AttackPath] = []
        for rule in self.rules:
            results = rule.evaluate(findings, store)
            for result in results:
                paths.append(self._to_path(result))
        return self._dedupe(paths)

    def _to_path(self, result: CorrelationResult) -> AttackPath:
        self._counter += 1
        return AttackPath(
            id=f"AP-{self._counter:04d}",
            rule_id=result.rule_id,
            title=result.title,
            narrative=result.narrative,
            category=result.category,
            status=result.status,
            severity=result.severity,
            confidence=result.confidence,
            finding_ids=tuple(result.finding_ids),
            entry_point=result.entry_point,
            target=result.target,
            validation_steps=tuple(result.validation_steps),
            references=tuple(result.references),
            tags=tuple(result.tags),
        )

    @staticmethod
    def _dedupe(paths: list[AttackPath]) -> list[AttackPath]:
        seen: set[tuple[str, tuple[str, ...]]] = set()
        out: list[AttackPath] = []
        for p in paths:
            key = (p.rule_id, p.finding_ids)
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
        return out
