"""Unit tests for PackagesVulnerableRule."""

from __future__ import annotations

from nexus_r.analysis import Confidence, Severity
from nexus_r.analysis.rules.packages_vulnerable import PackagesVulnerableRule
from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def _pkg(name: str, version: str) -> Evidence:
    return Evidence(
        id=f"pkg-{abs(hash((name, version))) % 10000:04d}",
        type=EvidenceType.PACKAGE,
        source="packages",
        data={"name": name, "version": version, "architecture": "amd64"},
    )


def _cves_in(results) -> set[str]:
    out: set[str] = set()
    for r in results:
        for t in r.tags:
            if t.startswith("CVE-"):
                out.add(t)
    return out


def test_empty_store() -> None:
    assert PackagesVulnerableRule().evaluate(EvidenceStore()) == []


def test_vulnerable_sudo_sudoedit() -> None:
    store = EvidenceStore()
    store.add(_pkg("sudo", "1.9.12"))
    results = PackagesVulnerableRule().evaluate(store)
    assert len(results) >= 1
    titles = " ".join(r.title for r in results)
    assert "CVE-2023-22809" in titles


def test_fixed_sudo() -> None:
    store = EvidenceStore()
    store.add(_pkg("sudo", "1.9.15p5"))
    assert PackagesVulnerableRule().evaluate(store) == []


def test_regresshion_critical() -> None:
    store = EvidenceStore()
    store.add(_pkg("openssh-server", "9.6p1"))
    results = PackagesVulnerableRule().evaluate(store)
    assert len(results) >= 1
    cves = _cves_in(results)
    assert "CVE-2024-6387" in cves
    # regreSSHion is CRITICAL
    assert any(r.severity == Severity.CRITICAL for r in results)


def test_xz_backdoor() -> None:
    store = EvidenceStore()
    store.add(_pkg("xz-utils", "5.6.1"))
    results = PackagesVulnerableRule().evaluate(store)
    cves = _cves_in(results)
    assert "CVE-2024-3094" in cves


def test_unrelated_package_ignored() -> None:
    store = EvidenceStore()
    store.add(_pkg("nginx", "1.24.0"))
    # nginx 1.24.0 is newer than 1.20.1, no 2023/2024 entry matches
    assert PackagesVulnerableRule().evaluate(store) == []


def test_multiple_cves_on_openssh() -> None:
    """openssh-server has two 2024 CVEs (regreSSHion + privsep)."""
    store = EvidenceStore()
    store.add(_pkg("openssh-server", "9.6p1"))
    results = PackagesVulnerableRule().evaluate(store)
    cves = _cves_in(results)
    assert "CVE-2024-6387" in cves
    assert "CVE-2024-6409" in cves


def test_confidence_medium() -> None:
    store = EvidenceStore()
    store.add(_pkg("sudo", "1.9.12"))
    results = PackagesVulnerableRule().evaluate(store)
    assert all(r.confidence == Confidence.MEDIUM for r in results)


def test_severity_from_database() -> None:
    """Severity in the finding comes from the database entry."""
    store = EvidenceStore()
    store.add(_pkg("xz-utils", "5.6.1"))
    results = PackagesVulnerableRule().evaluate(store)
    # xz backdoor is CRITICAL
    assert any(r.severity == Severity.CRITICAL for r in results)
