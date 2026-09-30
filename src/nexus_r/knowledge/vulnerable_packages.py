"""Curated database of known-vulnerable package versions.

This is intentionally small. It covers packages most commonly involved
in Linux privilege escalation. It is NOT a substitute for a real CVE
feed. Adding entries is easy and does not require changing any rule.

Version comparison is best-effort: it handles common version shapes
(``1.9.5p2``, ``1.9.5p2-1ubuntu1``) but does not fully implement
Debian version semantics (e.g. tilde pre-releases).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from nexus_r.analysis.finding import Severity


@dataclass(frozen=True)
class VulnerablePackageEntry:
    """A single (package, affected_below, CVE) mapping."""

    package: str
    affected_below: str
    cve: str
    nickname: str
    severity: Severity
    description: str
    references: tuple[str, ...] = ()


VULNERABLE_PACKAGES: tuple[VulnerablePackageEntry, ...] = (
    VulnerablePackageEntry(
        package="sudo",
        affected_below="1.9.5p2",
        cve="CVE-2021-3156",
        nickname="Baron Samedit",
        severity=Severity.CRITICAL,
        description=(
            "Heap-based buffer overflow in sudo argument parsing allows "
            "any local user to gain root."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2021-3156",),
    ),
    VulnerablePackageEntry(
        package="sudo",
        affected_below="1.9.12p2",
        cve="CVE-2023-22809",
        nickname="sudoedit -e bypass",
        severity=Severity.HIGH,
        description=(
            "sudoedit allows a user with sudoedit privileges to edit "
            "arbitrary files as root."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-22809",),
    ),
    VulnerablePackageEntry(
        package="sudo",
        affected_below="1.8.28",
        cve="CVE-2019-14287",
        nickname="sudo -u#-1 bypass",
        severity=Severity.HIGH,
        description=(
            "Sudo restriction bypass when a user is allowed to run "
            "commands as any user except root."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2019-14287",),
    ),
    VulnerablePackageEntry(
        package="policykit-1",
        affected_below="0.105-31.1",
        cve="CVE-2021-4034",
        nickname="PwnKit",
        severity=Severity.CRITICAL,
        description=(
            "Local privilege escalation in polkit's pkexec binary."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2021-4034",),
    ),
    VulnerablePackageEntry(
        package="bash",
        affected_below="4.3-7",
        cve="CVE-2014-6271",
        nickname="Shellshock",
        severity=Severity.CRITICAL,
        description=(
            "Bash processes trailing strings in environment variables, "
            "enabling remote code execution."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2014-6271",),
    ),
    VulnerablePackageEntry(
        package="glibc",
        affected_below="2.37-4",
        cve="CVE-2023-4911",
        nickname="Looney Tunables",
        severity=Severity.HIGH,
        description=(
            "Buffer overflow in ld.so's GLIBC_TUNABLES handling."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-4911",),
    ),
    VulnerablePackageEntry(
        package="openssl",
        affected_below="1.1.1n",
        cve="CVE-2022-0778",
        nickname="BN_mod_sqrt infinite loop",
        severity=Severity.MEDIUM,
        description=(
            "Infinite loop in BN_mod_sqrt() allows denial of service."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2022-0778",),
    ),
)


def _split_version(v: str) -> list[tuple[int, object]]:
    tokens = re.findall(r"\d+|[A-Za-z]+", v)
    out: list[tuple[int, object]] = []
    for t in tokens:
        if t.isdigit():
            out.append((1, int(t)))
        else:
            out.append((0, t.lower()))
    return out


def _compare_versions(a: str, b: str) -> int:
    """Return -1 if a<b, 0 if equal, 1 if a>b. Best-effort."""
    ta, tb = _split_version(a), _split_version(b)
    for x, y in zip(ta, tb):
        if x != y:
            return -1 if x < y else 1
    if len(ta) < len(tb):
        return -1
    if len(ta) > len(tb):
        return 1
    return 0


def is_affected(version: str, affected_below: str) -> bool:
    """True if version is strictly below affected_below."""
    return _compare_versions(version, affected_below) < 0


def find_vulnerable(name: str, version: str) -> list[VulnerablePackageEntry]:
    """Return entries matching (name, version). Empty if none."""
    return [
        e
        for e in VULNERABLE_PACKAGES
        if e.package == name and is_affected(version, e.affected_below)
    ]
