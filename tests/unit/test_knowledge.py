"""Unit tests for the knowledge engine."""

from __future__ import annotations

from nexus_r.knowledge import KNOWLEDGE, KnowledgeEntry, enrich_report
from nexus_r.knowledge.mappings import get_knowledge


def test_known_rule_returns_entry() -> None:
    entry = get_knowledge("NEXUS-SUID-001")
    assert entry is not None
    assert isinstance(entry, KnowledgeEntry)
    assert "CWE-269" in entry.cwe
    assert "T1548.001" in entry.attack


def test_unknown_rule_returns_none() -> None:
    assert get_knowledge("NEXUS-DOES-NOT-EXIST") is None


def test_all_entries_have_something() -> None:
    """Every entry should provide at least CWE or ATT&CK."""
    for rule_id, entry in KNOWLEDGE.items():
        assert entry.cwe or entry.attack, f"{rule_id} has no CWE or ATT&CK"


def test_correlation_rules_have_entries() -> None:
    for rule_id in (
        "NEXUS-CORR-DOCKER-001",
        "NEXUS-CORR-LXD-001",
        "NEXUS-CORR-SSH-001",
    ):
        assert rule_id in KNOWLEDGE


def test_enrich_report_adds_knowledge_to_findings() -> None:
    report = {
        "findings": [
            {"rule_id": "NEXUS-SUID-001", "title": "x"},
            {"rule_id": "NEXUS-UNKNOWN-999", "title": "y"},
        ],
        "attack_paths": [
            {"rule_id": "NEXUS-CORR-DOCKER-001", "title": "z"},
        ],
    }
    enrich_report(report)

    f0 = report["findings"][0]
    assert "knowledge" in f0
    assert "CWE-269" in f0["knowledge"]["cwe"]
    assert "T1548.001" in f0["knowledge"]["attack"]

    # Unknown rule -> no knowledge key added
    assert "knowledge" not in report["findings"][1]

    p0 = report["attack_paths"][0]
    assert "knowledge" in p0
    assert "T1610" in p0["knowledge"]["attack"]


def test_enrich_report_is_idempotent() -> None:
    report = {
        "findings": [{"rule_id": "NEXUS-SUDO-001", "title": "x"}],
        "attack_paths": [],
    }
    enrich_report(report)
    enrich_report(report)
    assert "knowledge" in report["findings"][0]
