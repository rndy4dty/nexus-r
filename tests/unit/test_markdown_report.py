"""Unit tests for the Markdown report builder."""

from __future__ import annotations

from pathlib import Path

from nexus_r.report.markdown_report import (
    build_markdown_report,
    write_markdown_report,
)


def _report() -> dict:
    return {
        "nexus_r_version": "0.6.0",
        "generated_at": "2026-10-01T12:00:00Z",
        "scan": {"collectors_run": ["system", "suid"], "collectors_failed": []},
        "evidence": [
            {
                "id": "sys-0001",
                "type": "system",
                "source": "system",
                "data": {"hostname": "test-host"},
            },
            {
                "id": "suid-0001",
                "type": "suid",
                "source": "suid",
                "data": {"path": "/usr/bin/find"},
            },
        ],
        "findings": [
            {
                "id": "F-0001",
                "rule_id": "NEXUS-SUID-001",
                "title": "SUID find",
                "description": "GTFOBins binary",
                "severity": "high",
                "confidence": "medium",
                "category": "privilege-escalation",
                "evidence_ids": ["suid-0001"],
                "validation_steps": ["ls -la /usr/bin/find"],
                "references": ["https://gtfobins.github.io"],
                "knowledge": {
                    "cwe": ["CWE-269"],
                    "attack": ["T1548.001"],
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
                "references": ["https://example.com"],
                "knowledge": {"cwe": ["CWE-269"], "attack": ["T1610"]},
            }
        ],
        "hypotheses": [
            {
                "id": "H-0001",
                "title": "privilege-escalation: 1 finding(s)",
                "narrative": "Check each finding.",
                "severity": "high",
                "confidence": "medium",
                "mode": "template",
                "model": "template",
                "status": "needs_review",
                "finding_ids": ["F-0001"],
                "validation_steps": ["step 1"],
            }
        ],
        "summary": {
            "evidence_count": 2,
            "finding_count": 1,
            "attack_path_count": 1,
            "hypothesis_count": 1,
            "findings_by_severity": {"high": 1},
            "findings_by_confidence": {"medium": 1},
        },
    }


def test_build_returns_string() -> None:
    md = build_markdown_report(_report())
    assert isinstance(md, str)
    assert len(md) > 100


def test_hostname_in_header() -> None:
    md = build_markdown_report(_report())
    assert "test-host" in md


def test_summary_table() -> None:
    md = build_markdown_report(_report())
    assert "| Findings | 1 |" in md
    assert "| Attack paths | 1 |" in md
    assert "| Hypotheses | 1 |" in md


def test_attack_path_section() -> None:
    md = build_markdown_report(_report())
    assert "## Attack Paths" in md
    assert "NEXUS-CORR-DOCKER-001" in md
    assert "plausible" in md


def test_finding_section() -> None:
    md = build_markdown_report(_report())
    assert "## Findings" in md
    assert "NEXUS-SUID-001" in md
    assert "CWE-269" in md
    assert "T1548.001" in md


def test_hypothesis_section() -> None:
    md = build_markdown_report(_report())
    assert "## Hypotheses" in md
    assert "H-0001" in md
    assert "needs_review" in md


def test_empty_report_does_not_crash() -> None:
    empty = {
        "nexus_r_version": "0.6.0",
        "generated_at": "",
        "scan": {},
        "evidence": [],
        "findings": [],
        "attack_paths": [],
        "hypotheses": [],
        "summary": {},
    }
    md = build_markdown_report(empty)
    assert "No findings" in md
    assert "No attack paths detected" in md


def test_write_creates_file(tmp_path: Path) -> None:
    path = write_markdown_report(_report(), tmp_path)
    assert path.exists()
    assert path.name == "report.md"
    content = path.read_text()
    assert "NEXUS-R" in content
    assert "test-host" in content


def test_escapes_pipes_in_titles() -> None:
    report = _report()
    report["findings"][0]["title"] = "evil | injection"
    md = build_markdown_report(report)
    assert "evil \\| injection" in md
