"""Unit tests for the HTML report builder."""

from __future__ import annotations

from pathlib import Path

from nexus_r.report.html_report import build_html_report, write_html_report


def _minimal_report() -> dict:
    return {
        "nexus_r_version": "0.1.0",
        "generated_at": "2026-10-01T12:00:00Z",
        "scan": {
            "collectors_run": ["system", "users"],
            "collectors_failed": [],
        },
        "evidence": [
            {
                "id": "sys-0001",
                "type": "system",
                "source": "system",
                "data": {"hostname": "test-host"},
            }
        ],
        "findings": [
            {
                "id": "F-0001",
                "rule_id": "TEST-001",
                "title": "Test finding",
                "description": "Description here",
                "severity": "high",
                "confidence": "medium",
                "evidence_ids": ["sys-0001"],
                "validation_steps": ["step 1", "step 2"],
                "references": ["https://example.com"],
                "tags": ["test"],
            }
        ],
        "attack_paths": [
            {
                "id": "AP-0001",
                "rule_id": "CORR-001",
                "title": "Test path",
                "narrative": "Narrative here",
                "severity": "critical",
                "confidence": "high",
                "status": "plausible",
                "finding_ids": ["F-0001"],
                "entry_point": "user",
                "target": "root",
                "validation_steps": ["verify"],
                "references": ["https://example.com"],
                "tags": ["test"],
            }
        ],
        "summary": {
            "evidence_count": 1,
            "finding_count": 1,
            "attack_path_count": 1,
            "findings_by_severity": {"high": 1},
            "attack_paths_by_severity": {"critical": 1},
        },
    }


def test_build_html_returns_string() -> None:
    html = build_html_report(_minimal_report())
    assert isinstance(html, str)
    assert "<!DOCTYPE html>" in html
    assert "</html>" in html


def test_build_html_contains_hostname() -> None:
    html = build_html_report(_minimal_report())
    assert "test-host" in html


def test_build_html_contains_finding() -> None:
    html = build_html_report(_minimal_report())
    assert "Test finding" in html
    assert "TEST-001" in html
    assert "step 1" in html


def test_build_html_contains_attack_path() -> None:
    html = build_html_report(_minimal_report())
    assert "Test path" in html
    assert "CORR-001" in html
    assert "Narrative here" in html
    assert "PLAUSIBLE" in html


def test_build_html_escapes_user_data() -> None:
    report = _minimal_report()
    report["findings"][0]["title"] = "<script>alert(1)</script>"
    html = build_html_report(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_write_html_report_creates_file(tmp_path: Path) -> None:
    path = write_html_report(_minimal_report(), tmp_path)
    assert path.exists()
    assert path.name == "report.html"
    content = path.read_text(encoding="utf-8")
    assert "NEXUS-R" in content
    assert "test-host" in content


def test_empty_report_does_not_crash() -> None:
    empty = {
        "nexus_r_version": "0.1.0",
        "generated_at": "2026-10-01T12:00:00Z",
        "scan": {"collectors_run": [], "collectors_failed": []},
        "evidence": [],
        "findings": [],
        "attack_paths": [],
        "summary": {
            "evidence_count": 0,
            "finding_count": 0,
            "attack_path_count": 0,
            "findings_by_severity": {},
            "attack_paths_by_severity": {},
        },
    }
    html = build_html_report(empty)
    assert "No findings" in html
    assert "No attack paths detected" in html
