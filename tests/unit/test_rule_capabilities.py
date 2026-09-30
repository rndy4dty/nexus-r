"""Unit tests for CapabilitiesDangerousRule."""

from __future__ import annotations

from nexus_r.analysis import Confidence, Severity
from nexus_r.analysis.rules.capabilities_dangerous import CapabilitiesDangerousRule
from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def _file_evidence(ev_id: str, path: str, caps: str) -> Evidence:
    return Evidence(
        id=ev_id,
        type=EvidenceType.CAPABILITY,
        source="capabilities",
        data={"path": path, "capabilities": caps, "kind": "file"},
    )


def test_empty_store() -> None:
    assert CapabilitiesDangerousRule().evaluate(EvidenceStore()) == []


def test_ignores_process_kind() -> None:
    store = EvidenceStore()
    store.add(
        Evidence(
            id="cap-0001",
            type=EvidenceType.CAPABILITY,
            source="capabilities",
            data={"kind": "process", "capabilities": ["cap_setuid"]},
        )
    )
    assert CapabilitiesDangerousRule().evaluate(store) == []


def test_setuid_critical() -> None:
    store = EvidenceStore()
    store.add(_file_evidence("cap-0001", "/usr/bin/foo", "cap_setuid+ep"))
    results = CapabilitiesDangerousRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.CRITICAL
    assert "cap_setuid" in results[0].title


def test_sys_admin_critical() -> None:
    store = EvidenceStore()
    store.add(_file_evidence("cap-0001", "/usr/bin/bar", "cap_sys_admin+ep"))
    results = CapabilitiesDangerousRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.CRITICAL


def test_chown_medium() -> None:
    store = EvidenceStore()
    store.add(_file_evidence("cap-0001", "/usr/bin/baz", "cap_chown+ep"))
    results = CapabilitiesDangerousRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.MEDIUM


def test_benign_cap_ignored() -> None:
    store = EvidenceStore()
    store.add(_file_evidence("cap-0001", "/usr/bin/ping", "cap_net_raw+ep"))
    results = CapabilitiesDangerousRule().evaluate(store)
    assert results == []


def test_only_first_dangerous_cap_per_file() -> None:
    store = EvidenceStore()
    store.add(
        _file_evidence(
            "cap-0001",
            "/usr/bin/multi",
            "cap_setuid,cap_setgid,cap_sys_admin+ep",
        )
    )
    results = CapabilitiesDangerousRule().evaluate(store)
    assert len(results) == 1
