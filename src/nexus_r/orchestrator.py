"""Scan orchestrator.

V0.3 pipeline:

    CLI → Orchestrator → Collectors → EvidenceStore
        → RuleEngine → Findings
        → CorrelationEngine → AttackPaths
        → JSON + HTML Report
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nexus_r import __version__
from nexus_r.analysis import (
    AttackPath,
    CorrelationEngine,
    Finding,
    RuleEngine,
)
from nexus_r.collectors import get_collectors
from nexus_r.config import ScanConfig
from nexus_r.evidence import EvidenceStore
from nexus_r.report import write_html_report, write_json_report


@dataclass(slots=True)
class ScanResult:
    """Result of a scan."""

    report: dict[str, Any]
    evidence_count: int
    collector_count: int
    finding_count: int
    findings: list[Finding]
    attack_path_count: int
    attack_paths: list[AttackPath]
    report_path: Path
    html_report_path: Path
    collectors_failed: list[dict[str, str]] = field(default_factory=list)


class ScanOrchestrator:
    """Runs the NEXUS-R scan pipeline."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def run(self) -> ScanResult:
        """Execute the scan pipeline."""
        self.config.ensure_output_dir()

        store = EvidenceStore()
        collectors_run: list[str] = []
        collectors_failed: list[dict[str, str]] = []

        collectors = get_collectors(self.config.collectors)
        for collector in collectors:
            try:
                evidence = collector.collect()
                store.add_many(evidence)
                collectors_run.append(collector.name)
            except Exception as exc:  # noqa: BLE001
                collectors_failed.append(
                    {"name": collector.name, "error": str(exc)}
                )

        rule_engine = RuleEngine()
        findings = rule_engine.evaluate(store)

        corr_engine = CorrelationEngine()
        attack_paths = corr_engine.evaluate(findings, store)

        report = self._build_report(
            store=store,
            findings=findings,
            attack_paths=attack_paths,
            collectors_run=collectors_run,
            collectors_failed=collectors_failed,
        )

        report_path = write_json_report(report, self.config.output_dir)
        html_report_path = write_html_report(report, self.config.output_dir)

        return ScanResult(
            report=report,
            evidence_count=store.count(),
            collector_count=len(collectors_run),
            finding_count=len(findings),
            findings=findings,
            attack_path_count=len(attack_paths),
            attack_paths=attack_paths,
            report_path=report_path,
            html_report_path=html_report_path,
            collectors_failed=collectors_failed,
        )

    def _build_report(
        self,
        store: EvidenceStore,
        findings: list[Finding],
        attack_paths: list[AttackPath],
        collectors_run: list[str],
        collectors_failed: list[dict[str, str]],
    ) -> dict[str, Any]:
        from datetime import datetime, timezone

        return {
            "nexus_r_version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan": {
                "output_format": self.config.output_format,
                "collectors_requested": list(self.config.collectors),
                "collectors_run": collectors_run,
                "collectors_failed": collectors_failed,
            },
            "evidence": store.to_list(),
            "findings": [f.to_json_dict() for f in findings],
            "attack_paths": [p.to_json_dict() for p in attack_paths],
            "summary": {
                "evidence_count": store.count(),
                "collector_count": len(collectors_run),
                "finding_count": len(findings),
                "attack_path_count": len(attack_paths),
                "evidence_by_type": self._count_by_evidence_type(store),
                "findings_by_severity": self._count_findings(
                    findings, "severity"
                ),
                "findings_by_confidence": self._count_findings(
                    findings, "confidence"
                ),
                "attack_paths_by_severity": self._count_paths(
                    attack_paths, "severity"
                ),
            },
        }

    @staticmethod
    def _count_by_evidence_type(store: EvidenceStore) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in store:
            key = item.type.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @staticmethod
    def _count_findings(findings: list[Finding], attr: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            value = getattr(f, attr)
            key = value.value if hasattr(value, "value") else str(value)
            counts[key] = counts.get(key, 0) + 1
        return counts

    @staticmethod
    def _count_paths(paths: list[AttackPath], attr: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for p in paths:
            value = getattr(p, attr)
            key = value.value if hasattr(value, "value") else str(value)
            counts[key] = counts.get(key, 0) + 1
        return counts
