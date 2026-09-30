"""Unit tests for the SARIF report builder."""

from __future__ import annotations

import json
from pathlib import Path

from nexus_r.report.sarif_report import (
    SARIF_VERSION,
    build_sarif,
    write_sarif_report,
)


def _report() -> dict:
    return {
        "nexus_r_version": "0.4.0",
        "generated_at": "2026-10-01T12:00:00Z",
        "scan": {"collectors_run": ["system", "suid"], "collectors_failed": []},
        "evidence": [
            {
                "id": "suid-0001",
                "type": "suid",
                "source": "suid",
                "data": {"path": "/usr/bin/find", "mode": "0o4755"},
            }
        ],
        "findings": [
            {
                "id": "F-0001",
                "rule_id": "NEXUS-SUID-001",
                "title": "SUID find",
                "description": "GTFOBins binary",
                "severity": "high",
                "confidence": "medium",
                "evidence_ids": ["suid-0001"],
                "validation_steps": ["ls -la /usr/bin/find"],
                "knowledge": {
                    "cwe": ["CWE-269"],
                    "attack": ["T1548.001"],
                    "references": ["https://gtfobins.github.io"],
                },
            }
        ],
        "attack_paths": [
            {
                "id": "AP-0001",
                "rule_id": "NEXUS-CORR-DOCKER-001",
                "title": "docker -> root",
                "narrative": "escape via mount",
                "severity": "critical",
                "confidence": "high",
                "status": "plausible",
                "finding_ids": ["F-0001"],
                "entry_point": "user",
                "target": "root",
                "validation_steps": ["id"],
                "knowledge": {
                    "cwe": ["CWE-269"],
                    "attack": ["T1610"],
                    "references": [],
                },
            }
        ],
        "summary": {
            "evidence_count": 1,
            "finding_count": 1,
            "attack_path_count": 1,
        },
    }


def test_sarif_version_and_schema() -> None:
    sarif = build_sarif(_report())
    assert sarif["version"] == SARIF_VERSION
    assert "$schema" in sarif


def test_sarif_tool_name() -> None:
    sarif = build_sarif(_report())
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "NEXUS-R"
    assert driver["version"] == "0.4.0"


def test_sarif_rules_deduped() -> None:
    sarif = build_sarif(_report())
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert "NEXUS-SUID-001" in rule_ids
    assert "NEXUS-CORR-DOCKER-001" in rule_ids
    assert len(rule_ids) == len(set(rule_ids))


def test_sarif_severity_to_level() -> None:
    sarif = build_sarif(_report())
    results = sarif["runs"][0]["results"]
    suid = next(r for r in results if r["ruleId"] == "NEXUS-SUID-001")
    docker = next(r for r in results if r["ruleId"] == "NEXUS-CORR-DOCKER-001")
    assert suid["level"] == "error"
    assert docker["level"] == "error"


def test_sarif_location_from_evidence_path() -> None:
    sarif = build_sarif(_report())
    results = sarif["runs"][0]["results"]
    suid = next(r for r in results if r["ruleId"] == "NEXUS-SUID-001")
    assert "locations" in suid
    uri = suid["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "file:///usr/bin/find"


def test_sarif_attack_path_no_location() -> None:
    sarif = build_sarif(_report())
    results = sarif["runs"][0]["results"]
    docker = next(r for r in results if r["ruleId"] == "NEXUS-CORR-DOCKER-001")
    assert "locations" not in docker


def test_sarif_knowledge_in_rules() -> None:
    sarif = build_sarif(_report())
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    suid = next(r for r in rules if r["id"] == "NEXUS-SUID-001")
    assert "CWE-269" in suid["properties"]["cwe"]
    assert "T1548.001" in suid["properties"]["attack"]


def test_write_sarif_creates_file(tmp_path: Path) -> None:
    path = write_sarif_report(_report(), tmp_path)
    assert path.exists()
    assert path.name == "report.sarif"
    data = json.loads(path.read_text())
    assert data["version"] == SARIF_VERSION


def test_empty_report_does_not_crash() -> None:
    empty = {
        "nexus_r_version": "0.4.0",
        "generated_at": "",
        "scan": {},
        "evidence": [],
        "findings": [],
        "attack_paths": [],
        "summary": {},
    }
    sarif = build_sarif(empty)
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
