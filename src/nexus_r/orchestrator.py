"""Scan orchestrator.

Coordinates the pipeline described in ADR-001 §4:

    CLI → Orchestrator → Collectors → Normalization → Evidence → Report

In Step 3 this module returns an empty report skeleton. Later steps will
fill in collectors, evidence store, and reporter wiring without changing
the public interface (``ScanOrchestrator.run``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from nexus_r import __version__
from nexus_r.config import ScanConfig


@dataclass(slots=True)
class ScanResult:
    """Result returned by ScanOrchestrator.run.

    Attributes:
        report: JSON-serializable report dictionary.
        evidence_count: Number of evidence items collected.
        collector_count: Number of collectors executed.
    """

    report: dict[str, Any]
    evidence_count: int
    collector_count: int


class ScanOrchestrator:
    """Runs the NEXUS-R scan pipeline.

    Step 3: stub that produces an empty report skeleton.
    Step 11+: full pipeline.
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def run(self) -> ScanResult:
        """Execute the scan pipeline and return a ScanResult.

        Current behavior (Step 3):
            - Ensures the output directory exists.
            - Returns an empty report skeleton.
            - Does not yet invoke collectors, normalizer, or reporter.
        """
        self.config.ensure_output_dir()

        report: dict[str, Any] = {
            "nexus_r_version": __version__,
            "scan": {
                "output_format": self.config.output_format,
                "collectors": list(self.config.collectors),
            },
            "evidence": [],
            "summary": {
                "evidence_count": 0,
                "collector_count": 0,
            },
        }

        return ScanResult(
            report=report,
            evidence_count=0,
            collector_count=0,
        )
