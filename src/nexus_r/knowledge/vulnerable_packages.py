"""Curated database of known-vulnerable package versions.

Focused on CVEs from 2023 and 2024 that are relevant to Linux
privilege escalation, container escape, or remote code execution.

This is intentionally a curated subset, not a full CVE feed. Every
entry has an NVD reference. Adding entries is easy and does not
require changing any rule.

For 2025+ CVEs, add entries manually after verifying against NVD
(https://nvd.nist.gov). The comparison logic below is generic and
does not need to change.

Version comparison is best-effort: it handles common version shapes
(``1.9.5p2``, ``1.9.5p2-1ubuntu1``) but does not fully implement
Debian version semantics (e.g. tilde pre-releases).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerablePackageEntry:
    """A single (package, affected_below, CVE) mapping."""

    package: str
    affected_below: str
    cve: str
    nickname: str
    severity: str  # one of: critical, high, medium, low, info
    description: str
    references: tuple[str, ...] = ()


VULNERABLE_PACKAGES: tuple[VulnerablePackageEntry, ...] = (
    # =========================================================
    # 2023
    # =========================================================
    VulnerablePackageEntry(
        package="sudo",
        affected_below="1.9.12p2",
        cve="CVE-2023-22809",
        nickname="sudoedit -e bypass",
        severity="high",
        description=(
            "sudoedit does not properly validate EDITOR/VISUAL, "
            "allowing a user with sudoedit privileges to edit arbitrary "
            "files as root."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-22809",),
    ),
    VulnerablePackageEntry(
        package="glibc",
        affected_below="2.37-4",
        cve="CVE-2023-4911",
        nickname="Looney Tunables",
        severity="high",
        description=(
            "Buffer overflow in ld.so's GLIBC_TUNABLES handling allows "
            "local privilege escalation."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-4911",),
    ),
    VulnerablePackageEntry(
        package="openssh-client",
        affected_below="9.3p2",
        cve="CVE-2023-38408",
        nickname="ssh-agent PKCS#11 RCE",
        severity="high",
        description=(
            "Remote code execution in ssh-agent via forwarded PKCS#11 "
            "providers."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-38408",),
    ),
    VulnerablePackageEntry(
        package="systemd",
        affected_below="247.4",
        cve="CVE-2023-26604",
        nickname="systemctl pager privesc",
        severity="medium",
        description=(
            "systemctl does not drop privileges before invoking the "
            "configured pager, allowing privesc if LESSOPEN is set."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-26604",),
    ),
    VulnerablePackageEntry(
        package="curl",
        affected_below="8.4.0",
        cve="CVE-2023-38545",
        nickname="curl SOCKS5 heap overflow",
        severity="high",
        description=(
            "Heap-based buffer overflow in curl's SOCKS5 handshake."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-38545",),
    ),
    VulnerablePackageEntry(
        package="postgresql-14",
        affected_below="14.8",
        cve="CVE-2023-2454",
        nickname="PostgreSQL schema_element privesc",
        severity="medium",
        description=(
            "schema_element defeats protective search_path changes, "
            "allowing privilege escalation to superuser."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-2454",),
    ),
    VulnerablePackageEntry(
        package="python3.10",
        affected_below="3.10.12",
        cve="CVE-2023-24329",
        nickname="Python urllib URL bypass",
        severity="medium",
        description=(
            "urllib.parse mishandles URLs beginning with a blank "
            "character, allowing access control bypass."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-24329",),
    ),
    VulnerablePackageEntry(
        package="linux-image-generic",
        affected_below="6.2",
        cve="CVE-2023-0386",
        nickname="OverlayFS local privesc",
        severity="high",
        description=(
            "Linux kernel OverlayFS copy_up mishandling allows a local "
            "user to escalate to root."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-0386",),
    ),
    VulnerablePackageEntry(
        package="linux-image-generic",
        affected_below="6.3.2",
        cve="CVE-2023-32233",
        nickname="nf_tables UAF",
        severity="high",
        description=(
            "Use-after-free in netfilter nf_tables allows local "
            "privilege escalation to root."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-32233",),
    ),
    VulnerablePackageEntry(
        package="linux-image-generic",
        affected_below="6.4.6",
        cve="CVE-2023-35001",
        nickname="nftables nft_byteorder",
        severity="high",
        description=(
            "Out-of-bounds access in netfilter nftables allows local "
            "privilege escalation."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-35001",),
    ),
    VulnerablePackageEntry(
        package="golang-go",
        affected_below="1.20.10",
        cve="CVE-2023-39325",
        nickname="HTTP/2 Rapid Reset (Go)",
        severity="high",
        description=(
            "HTTP/2 rapid stream reset allows remote denial of service "
            "against Go's net/http server."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-39325",),
    ),
    VulnerablePackageEntry(
        package="apache2",
        affected_below="2.4.58",
        cve="CVE-2023-44487",
        nickname="HTTP/2 Rapid Reset (Apache)",
        severity="high",
        description=(
            "HTTP/2 rapid stream reset allows remote denial of service."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2023-44487",),
    ),

    # =========================================================
    # 2024
    # =========================================================
    VulnerablePackageEntry(
        package="openssh-server",
        affected_below="9.8p1",
        cve="CVE-2024-6387",
        nickname="regreSSHion",
        severity="critical",
        description=(
            "Signal handler race condition in OpenSSH server allows "
            "unauthenticated remote code execution as root (glibc-based "
            "Linux systems)."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-6387",),
    ),
    VulnerablePackageEntry(
        package="openssh-server",
        affected_below="9.8p1",
        cve="CVE-2024-6409",
        nickname="regreSSHion (privsep)",
        severity="high",
        description=(
            "Race condition in OpenSSH's privsep child allows code "
            "execution with reduced privileges."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-6409",),
    ),
    VulnerablePackageEntry(
        package="runc",
        affected_below="1.1.12",
        cve="CVE-2024-21626",
        nickname="runc file descriptor leak",
        severity="high",
        description=(
            "Container escape via leaked file descriptor in runc."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-21626",),
    ),
    VulnerablePackageEntry(
        package="xz-utils",
        affected_below="5.6.2",
        cve="CVE-2024-3094",
        nickname="xz backdoor",
        severity="critical",
        description=(
            "Malicious code in xz/liblzma (versions 5.6.0 and 5.6.1) "
            "allows remote code execution against sshd via a modified "
            "liblzma."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-3094",),
    ),
    VulnerablePackageEntry(
        package="less",
        affected_below="643",
        cve="CVE-2024-32487",
        nickname="less filename injection",
        severity="medium",
        description=(
            "less mishandles filenames containing newlines, allowing "
            "arbitrary command execution."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-32487",),
    ),
    VulnerablePackageEntry(
        package="linux-image-generic",
        affected_below="6.8",
        cve="CVE-2024-1086",
        nickname="nf_tables UAF (2024)",
        severity="high",
        description=(
            "Use-after-free in netfilter nf_tables allows local "
            "privilege escalation to root."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-1086",),
    ),
    VulnerablePackageEntry(
        package="linux-image-generic",
        affected_below="6.8",
        cve="CVE-2024-26581",
        nickname="nf_tables rbtree",
        severity="high",
        description=(
            "Double-free in netfilter nft_set_rbtree allows local "
            "privilege escalation."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-26581",),
    ),
    VulnerablePackageEntry(
        package="glibc",
        affected_below="2.40",
        cve="CVE-2024-2961",
        nickname="glibc iconv buffer overflow",
        severity="high",
        description=(
            "Out-of-bounds write in the ISO-2022-CN-EXT converter in "
            "glibc iconv."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-2961",),
    ),
    VulnerablePackageEntry(
        package="php",
        affected_below="8.3.8",
        cve="CVE-2024-4577",
        nickname="PHP CGI argument injection",
        severity="critical",
        description=(
            "PHP CGI argument injection allows remote code execution on "
            "Windows and some misconfigured Unix setups."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-4577",),
    ),
    VulnerablePackageEntry(
        package="cups-browsed",
        affected_below="2.0.1",
        cve="CVE-2024-47176",
        nickname="CUPS chain (cups-browsed)",
        severity="high",
        description=(
            "cups-browsed binds to UDP 631 and trusts untrusted packets, "
            "part of a chain that enables remote code execution."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-47176",),
    ),
    VulnerablePackageEntry(
        package="libcupsfilters",
        affected_below="2.1.0",
        cve="CVE-2024-47076",
        nickname="CUPS chain (libcupsfilters)",
        severity="high",
        description=(
            "libcupsfilters does not validate attributes from IPP "
            "servers, part of the CUPS RCE chain."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-47076",),
    ),
    VulnerablePackageEntry(
        package="libppd",
        affected_below="2.1.0",
        cve="CVE-2024-47175",
        nickname="CUPS chain (libppd)",
        severity="high",
        description=(
            "libppd does not sanitize IPP attributes when writing PPD "
            "files, part of the CUPS RCE chain."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-47175",),
    ),
    VulnerablePackageEntry(
        package="cups-filters",
        affected_below="2.0.1",
        cve="CVE-2024-47177",
        nickname="CUPS chain (cups-filters)",
        severity="high",
        description=(
            "cups-filters allows command injection via the FoomaticRIP "
            "options, final step of the CUPS RCE chain."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-47177",),
    ),
    VulnerablePackageEntry(
        package="apache2",
        affected_below="2.4.59",
        cve="CVE-2024-27316",
        nickname="Apache HTTP/2 memory exhaustion",
        severity="high",
        description=(
            "HTTP/2 continuation flood allows remote memory exhaustion "
            "in Apache httpd."
        ),
        references=("https://nvd.nist.gov/vuln/detail/CVE-2024-27316",),
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
