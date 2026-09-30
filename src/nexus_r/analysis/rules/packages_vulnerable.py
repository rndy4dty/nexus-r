"""Detect installed packages with known vulnerable versions."""

from __future__ import annotations

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType
from nexus_r.knowledge.vulnerable_packages import find_vulnerable


class PackagesVulnerableRule(Rule):
    """Flags installed packages affected by a known CVE."""

    id = "NEXUS-PKG-001"
    title = "Installed package has known CVE"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.PACKAGE):
            name = ev.data.get("name", "")
            version = ev.data.get("version", "")
            if not name or not version:
                continue

            for entry in find_vulnerable(name, version):
                title = f"{entry.cve} in {name} {version}"
                if entry.nickname:
                    title = f"{entry.cve} ({entry.nickname}) in {name} {version}"
                results.append(
                    RuleResult(
                        rule_id=self.id,
                        title=title,
                        description=(
                            f"Installed package {name} {version} is below "
                            f"{entry.affected_below}, which is affected by "
                            f"{entry.cve}. {entry.description}"
                        ),
                        category="vulnerable-package",
                        severity=entry.severity,
                        confidence=Confidence.MEDIUM,
                        evidence_ids=[ev.id],
                        validation_steps=[
                            f"Check installed version: dpkg -l {name}",
                            f"Look up {entry.cve} for this distribution.",
                            "Confirm the exploitability path before testing.",
                            "Do NOT run public exploits on production.",
                        ],
                        references=list(entry.references),
                        tags=["package", "cve", entry.cve],
                    )
                )
        return results
