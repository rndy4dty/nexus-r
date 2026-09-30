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


def test_find_vulnerable_sudo_old() -> None:
    matches = find_vulnerable("sudo", "1.8.0")
    cves = {m.cve for m in matches}
    assert "CVE-2021-3156" in cves
    assert "CVE-2019-14287" in cves


def test_find_vulnerable_sudo_fixed() -> None:
    matches = find_vulnerable("sudo", "1.9.15p5")
    assert matches == []


def test_find_vulnerable_unknown_package() -> None:
    assert find_vulnerable("not-a-real-package", "1.0.0") == []


def test_pwnkit() -> None:
    matches = find_vulnerable("policykit-1", "0.105-25")
    cves = {m.cve for m in matches}
    assert "CVE-2021-4034" in cves
