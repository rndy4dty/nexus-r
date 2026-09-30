"""Rule engine.

Runs registered rules against the evidence store and produces
deduplicated Findings with deterministic IDs.
"""

from __future__ import annotations

from nexus_r.analysis.finding import Finding
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.analysis.rules import get_rules
from nexus_r.evidence import EvidenceStore


class RuleEngine:
    """Executes rules and produces findings."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else get_rules()
        self._counter = 0

    def evaluate(self, store: EvidenceStore) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.rules:
            results = rule.evaluate(store)
            for result in results:
                findings.append(self._to_finding(result))
        return self._dedupe(findings)

    def _to_finding(self, result: RuleResult) -> Finding:
        self._counter += 1
        return Finding(
            id=f"F-{self._counter:04d}",
            rule_id=result.rule_id,
            title=result.title,
            description=result.description,
            category=result.category,
            severity=result.severity,
            confidence=result.confidence,
            evidence_ids=tuple(result.evidence_ids),
            validation_steps=tuple(result.validation_steps),
            references=tuple(result.references),
            tags=tuple(result.tags),
        )

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, tuple[str, ...]]] = set()
        out: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.evidence_ids)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out
