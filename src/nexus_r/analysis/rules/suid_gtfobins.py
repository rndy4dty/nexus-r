"""Detect SUID binaries matching GTFOBins."""

from __future__ import annotations

from pathlib import Path

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.analysis.rules.gtfobins_data import GTFOBINS
from nexus_r.evidence import EvidenceStore, EvidenceType


class SuidGtfobinsRule(Rule):
    """Flags SUID binaries whose name matches a known GTFOBins entry."""

    id = "NEXUS-SUID-001"
    title = "SUID binary matches GTFOBins"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.SUID):
            path = ev.data.get("path", "")
            if not path:
                continue
            name = Path(path).name
            if name not in GTFOBINS:
                continue
            results.append(
                RuleResult(
                    rule_id=self.id,
                    title=f"SUID {name} — known GTFOBins privesc vector",
                    description=(
                        f"SUID binary '{path}' matches a known GTFOBins "
                        "privilege-escalation vector. Validate manually."
                    ),
                    category="privilege-escalation",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    evidence_ids=[ev.id],
                    validation_steps=[
                        f"Check: ls -la {path}",
                        f"Look up {name}: https://gtfobins.github.io/gtfobins/{name}/",
                        "Reproduce in a lab container, never on production.",
                    ],
                    references=[
                        "https://gtfobins.github.io",
                        "MITRE ATT&CK T1548.001",
                    ],
                    tags=["suid", "gtfobins"],
                )
            )
        return results
