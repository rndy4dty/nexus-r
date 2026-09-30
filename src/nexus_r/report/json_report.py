"""JSON report helpers.

The orchestrator builds the report dict directly and writes it via
`write_json_report`. This module also exposes `build_report` for
callers that want to build a report from parts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_json_report(
    report: dict[str, Any],
    output_dir: Path,
    filename: str = "report.json",
) -> Path:
    """Write the report dict as JSON and return the path."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


def build_report(
    *,
    nexus_r_version: str,
    scan: dict[str, Any],
    evidence: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    attack_paths: list[dict[str, Any]],
    summary: dict[str, Any],
) -> dict[str, Any]:
    """Build a JSON report dict from its parts."""
    return {
        "nexus_r_version": nexus_r_version,
        "scan": scan,
        "evidence": evidence,
        "findings": findings,
        "attack_paths": attack_paths,
        "summary": summary,
    }


def write_report(report: dict[str, Any], output_dir: Path) -> Path:
    """Backwards-compatible alias for write_json_report."""
    return write_json_report(report, output_dir)
