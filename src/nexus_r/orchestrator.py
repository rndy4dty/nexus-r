"""Scan orchestrator.

V0.1 pipeline:

    CLI → Orchestrator → Collectors → EvidenceStore → JSON Report

Rule engine integration comes in Step 3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nexus_r import __version__
from nexus_r.collectors import get_collectors
from nexus_r.config import ScanConfig
from nexus_r.evidence import EvidenceStore


@dataclass(slots=True)
class ScanResult:
    """Result of a scan."""

    report: dict[str, Any]
    evidence_count: int
    collector_count: int
    report_path: Path
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

        report = self._build_report(
            store=store,
            collectors_run=collectors_run,
            collectors_failed=collectors_failed,
        )

        report_path = self._write_report(report)

        return ScanResult(
            report=report,
            evidence_count=store.count(),
            collector_count=len(collectors_run),
            report_path=report_path,
            collectors_failed=collectors_failed,
        )

    def _build_report(
        self,
        store: EvidenceStore,
        collectors_run: list[str],
        collectors_failed: list[dict[str, str]],
    ) -> dict[str, Any]:
        return {
            "nexus_r_version": __version__,
            "scan": {
                "output_format": self.config.output_format,
                "collectors_requested": list(self.config.collectors),
                "collectors_run": collectors_run,
                "collectors_failed": collectors_failed,
            },
            "evidence": store.to_list(),
            "summary": {
                "evidence_count": store.count(),
                "collector_count": len(collectors_run),
                "by_type": self._count_by_type(store),
            },
        }

    @staticmethod
    def _count_by_type(store: EvidenceStore) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in store:
            key = item.type.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _write_report(self, report: dict[str, Any]) -> Path:
        import json

        output_dir = self.config.output_dir
        path = output_dir / "report.json"
        path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return path
