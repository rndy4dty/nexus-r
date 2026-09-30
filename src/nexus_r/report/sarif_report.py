"""SARIF 2.1.0 report builder.

Converts a NEXUS-R report dict into a SARIF 2.1.0 document, suitable
for upload to GitHub Code Scanning, GitLab SAST, or any SARIF-aware
CI system.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "NEXUS-R"
TOOL_URI = "https://github.com/nexus-r/nexus-r"

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _path_from_evidence(
    finding: dict[str, Any], evidence_index: dict[str, dict[str, Any]]
) -> str | None:
    """Return a filesystem path if any of the finding's evidence has one."""
    for ev_id in finding.get("evidence_ids", []):
        ev = evidence_index.get(ev_id)
        if not ev:
            continue
        data = ev.get("data", {})
        path = data.get("path") or data.get("real_path")
        if isinstance(path, str) and path.startswith("/"):
            return path
    return None


def _to_uri(path: str) -> str:
    if path.startswith("/"):
        return f"file://{path}"
    return path


def _build_rules(
    findings: list[dict[str, Any]],
    attack_paths: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the SARIF `rules` array, one entry per unique rule_id."""
    seen: dict[str, dict[str, Any]] = {}

    def add(item: dict[str, Any], is_path: bool) -> None:
        rid = item.get("rule_id")
        if not rid or rid in seen:
            return
        knowledge = item.get("knowledge", {})
        refs = list(knowledge.get("references", []))
        # Also pull the first reference from validation if no knowledge refs
        if not refs:
            refs = list(item.get("references", []))
        help_uri = refs[0] if refs else TOOL_URI

        rule: dict[str, Any] = {
            "id": rid,
            "name": rid,
            "shortDescription": {"text": item.get("title", rid)},
            "helpUri": help_uri,
            "properties": {
                "severity": item.get("severity", "info"),
                "confidence": item.get("confidence", "low"),
                "kind": "attack-path" if is_path else "finding",
            },
        }
        if knowledge:
            rule["properties"]["cwe"] = list(knowledge.get("cwe", []))
            rule["properties"]["attack"] = list(knowledge.get("attack", []))
        seen[rid] = rule

    for f in findings:
        add(f, is_path=False)
    for p in attack_paths:
        add(p, is_path=True)

    return list(seen.values())


def _build_results(
    findings: list[dict[str, Any]],
    attack_paths: list[dict[str, Any]],
    evidence_index: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Build the SARIF `results` array."""
    results: list[dict[str, Any]] = []

    for f in findings:
        level = SEVERITY_TO_SARIF_LEVEL.get(f.get("severity", "info"), "note")
        path = _path_from_evidence(f, evidence_index)
        result: dict[str, Any] = {
            "ruleId": f.get("rule_id", "UNKNOWN"),
            "level": level,
            "message": {"text": f"{f.get('title', '')}. {f.get('description', '')}".strip()},
            "properties": {
                "confidence": f.get("confidence", "low"),
                "evidence_ids": list(f.get("evidence_ids", [])),
                "validation_steps": list(f.get("validation_steps", [])),
            },
        }
        if path:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _to_uri(path)},
                    }
                }
            ]
        results.append(result)

    for p in attack_paths:
        level = SEVERITY_TO_SARIF_LEVEL.get(p.get("severity", "info"), "note")
        results.append(
            {
                "ruleId": p.get("rule_id", "UNKNOWN"),
                "level": level,
                "message": {
                    "text": (
                        f"{p.get('title', '')}. "
                        f"Entry: {p.get('entry_point', '?')} -> "
                        f"Target: {p.get('target', '?')}. "
                        f"{p.get('narrative', '')}"
                    ).strip()
                },
                "properties": {
                    "confidence": p.get("confidence", "low"),
                    "status": p.get("status", "plausible"),
                    "finding_ids": list(p.get("finding_ids", [])),
                    "validation_steps": list(p.get("validation_steps", [])),
                },
            }
        )

    return results


def build_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document from a NEXUS-R report dict."""
    findings = report.get("findings", [])
    attack_paths = report.get("attack_paths", [])
    evidence = report.get("evidence", [])

    evidence_index: dict[str, dict[str, Any]] = {
        ev.get("id", ""): ev for ev in evidence if ev.get("id")
    }

    rules = _build_rules(findings, attack_paths)
    results = _build_results(findings, attack_paths, evidence_index)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": report.get("nexus_r_version", "0.0.0"),
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "generated_at": report.get("generated_at", ""),
                    "collectors_run": report.get("scan", {}).get(
                        "collectors_run", []
                    ),
                    "summary": report.get("summary", {}),
                },
            }
        ],
    }


def write_sarif_report(
    report: dict[str, Any],
    output_dir: Path,
    filename: str = "report.sarif",
) -> Path:
    """Write the SARIF report and return the file path."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(
        json.dumps(build_sarif(report), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path
