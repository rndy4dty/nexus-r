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


def test_vulnerable_sudo() -> None:
    store = EvidenceStore()
    store.add(_pkg("sudo", "1.8.0"))
    results = PackagesVulnerableRule().evaluate(store)
    assert len(results) >= 1
    titles = " ".join(r.title for r in results)
    assert "CVE-2021-3156" in titles


def test_fixed_sudo() -> None:
    store = EvidenceStore()
    store.add(_pkg("sudo", "1.9.15p5"))
    assert PackagesVulnerableRule().evaluate(store) == []


def test_vulnerable_polkit() -> None:
    store = EvidenceStore()
    store.add(_pkg("policykit-1", "0.105-25"))
    results = PackagesVulnerableRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.CRITICAL
    assert "PwnKit" in results[0].title


def test_unrelated_package_ignored() -> None:
    store = EvidenceStore()
    store.add(_pkg("nginx", "1.24.0"))
    assert PackagesVulnerableRule().evaluate(store) == []


def test_multiple_cves_on_one_package() -> None:
    store = EvidenceStore()
    store.add(_pkg("sudo", "1.8.0"))
    results = PackagesVulnerableRule().evaluate(store)
    cves = _cves_in(results)
    assert "CVE-2021-3156" in cves
    assert "CVE-2019-14287" in cves


def test_confidence_medium() -> None:
    store = EvidenceStore()
    store.add(_pkg("sudo", "1.8.0"))
    results = PackagesVulnerableRule().evaluate(store)
    assert all(r.confidence == Confidence.MEDIUM for r in results)
