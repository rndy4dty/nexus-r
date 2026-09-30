"""Unit tests for the vulnerable package database."""

from __future__ import annotations

from nexus_r.knowledge.vulnerable_packages import (
    _compare_versions,
    find_vulnerable,
    is_affected,
)


def test_compare_basic() -> None:
    assert _compare_versions("1.8.0", "1.9.5p2") < 0
    assert _compare_versions("1.9.5p2", "1.9.5p2") == 0
    assert _compare_versions("1.9.5p3", "1.9.5p2") > 0


def test_compare_with_suffix() -> None:
    assert _compare_versions("1.9.5p2-1ubuntu1", "1.9.5p2") > 0
    assert _compare_versions("1.9.5p1-1ubuntu1", "1.9.5p2") < 0


def test_is_affected_true() -> None:
    assert is_affected("1.8.0", "1.9.5p2")


def test_is_affected_equal() -> None:
    assert not is_affected("1.9.5p2", "1.9.5p2")


def test_is_affected_newer() -> None:
    assert not is_affected("1.9.6", "1.9.5p2")


def test_find_vulnerable_sudo_sudoedit() -> None:
    """sudo below 1.9.12p2 is affected by CVE-2023-22809."""
    matches = find_vulnerable("sudo", "1.9.12")
    cves = {m.cve for m in matches}
    assert "CVE-2023-22809" in cves


def test_find_vulnerable_sudo_fixed() -> None:
    """Newer sudo should not match any 2023/2024 entry."""
    matches = find_vulnerable("sudo", "1.9.15p5")
    assert matches == []


def test_find_vulnerable_unknown_package() -> None:
    assert find_vulnerable("not-a-real-package", "1.0.0") == []


def test_regresshion() -> None:
    """OpenSSH server below 9.8p1 is affected by CVE-2024-6387."""
    matches = find_vulnerable("openssh-server", "9.6p1")
    cves = {m.cve for m in matches}
    assert "CVE-2024-6387" in cves


def test_regresshion_fixed() -> None:
    """OpenSSH 9.8p1+ is not affected by regreSSHion."""
    matches = find_vulnerable("openssh-server", "9.9p1")
    assert matches == []


def test_xz_backdoor() -> None:
    """xz-utils below 5.6.2 is affected by CVE-2024-3094."""
    matches = find_vulnerable("xz-utils", "5.6.1")
    cves = {m.cve for m in matches}
    assert "CVE-2024-3094" in cves


def test_looney_tunables() -> None:
    """glibc below 2.37-4 is affected by CVE-2023-4911."""
    matches = find_vulnerable("glibc", "2.36")
    cves = {m.cve for m in matches}
    assert "CVE-2023-4911" in cves


def test_kernel_privesc_2023() -> None:
    """Old kernel is affected by CVE-2023-0386 and others."""
    matches = find_vulnerable("linux-image-generic", "6.1")
    cves = {m.cve for m in matches}
    assert "CVE-2023-0386" in cves
    assert "CVE-2024-1086" in cves


def test_database_has_2023_and_2024() -> None:
    """The database must include CVEs from both years."""
    from nexus_r.knowledge.vulnerable_packages import VULNERABLE_PACKAGES

    years = {e.cve.split("-")[1] for e in VULNERABLE_PACKAGES}
    assert "2023" in years
    assert "2024" in years
