"""Unit tests for sudo rules."""

from __future__ import annotations

from nexus_r.analysis import Confidence, Severity
from nexus_r.analysis.rules.sudo_dangerous import SudoDangerousRule
from nexus_r.analysis.rules.sudo_nopasswd import SudoNopasswdRule
from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def _store_with_entries(entries: list[str]) -> EvidenceStore:
    store = EvidenceStore()
    for i, entry in enumerate(entries, start=1):
        store.add(
            Evidence(
                id=f"sudo-{i:04d}",
                type=EvidenceType.SUDO,
                source="sudo",
                data={
                    "path": "/etc/sudoers",
                    "line": i,
                    "entry": entry,
                    "readable": True,
                },
            )
        )
    return store


def test_nopasswd_empty_store() -> None:
    assert SudoNopasswdRule().evaluate(EvidenceStore()) == []


def test_nopasswd_detected() -> None:
    store = _store_with_entries(["rendy ALL=(ALL) NOPASSWD: /usr/bin/vim"])
    results = SudoNopasswdRule().evaluate(store)
    assert len(results) == 1
    r = results[0]
    assert r.rule_id == "NEXUS-SUDO-001"
    assert r.severity == Severity.HIGH
    assert r.confidence == Confidence.HIGH


def test_nopasswd_case_insensitive() -> None:
    store = _store_with_entries(["a ALL=(ALL) nopasswd: /bin/ls"])
    results = SudoNopasswdRule().evaluate(store)
    assert len(results) == 1


def test_nopasswd_not_matched() -> None:
    store = _store_with_entries(["root ALL=(ALL:ALL) ALL"])
    results = SudoNopasswdRule().evaluate(store)
    assert results == []


def test_nopasswd_skips_unreadable() -> None:
    store = EvidenceStore()
    store.add(
        Evidence(
            id="sudo-0001",
            type=EvidenceType.SUDO,
            source="sudo",
            data={"path": "/etc/sudoers", "readable": False},
        )
    )
    assert SudoNopasswdRule().evaluate(store) == []


def test_dangerous_wildcard() -> None:
    store = _store_with_entries(["a ALL=(ALL) NOPASSWD: /usr/bin/find /tmp/*"])
    results = SudoDangerousRule().evaluate(store)
    assert len(results) == 1
    assert "wildcard" in results[0].description.lower()


def test_dangerous_binary() -> None:
    store = _store_with_entries(["a ALL=(ALL) NOPASSWD: /usr/bin/vim"])
    results = SudoDangerousRule().evaluate(store)
    assert len(results) == 1
    assert "vim" in results[0].description.lower()


def test_dangerous_all_command() -> None:
    store = _store_with_entries(["a ALL=(ALL) ALL"])
    results = SudoDangerousRule().evaluate(store)
    assert len(results) == 1


def test_dangerous_skips_defaults() -> None:
    store = _store_with_entries(["Defaults env_reset", "Defaults secure_path=\"/usr/sbin\""])
    results = SudoDangerousRule().evaluate(store)
    assert results == []


def test_dangerous_no_match() -> None:
    store = _store_with_entries(["a ALL=(ALL) /usr/bin/ls /var/log"])
    results = SudoDangerousRule().evaluate(store)
    assert results == []
