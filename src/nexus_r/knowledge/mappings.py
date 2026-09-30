"""Rule → CWE / ATT&CK / reference mappings.

This is the single source of truth for the knowledge engine. Adding a
new rule does not require touching the rule itself; adding an entry
here is enough for the report to be enriched.

References:

- CWE: https://cwe.mitre.org
- MITRE ATT&CK: https://attack.mitre.org
- GTFOBins: https://gtfobins.github.io
- HackTricks: https://book.hacktricks.xyz
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KnowledgeEntry:
    """Knowledge enrichment for a single rule (finding or attack path)."""

    cwe: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


KNOWLEDGE: dict[str, KnowledgeEntry] = {
    # ----- SUID / SGID -----
    "NEXUS-SUID-001": KnowledgeEntry(
        cwe=("CWE-269", "CWE-250"),
        attack=("T1548.001",),
        references=(
            "https://gtfobins.github.io",
            "https://cwe.mitre.org/data/definitions/269.html",
            "https://attack.mitre.org/techniques/T1548/001/",
        ),
        notes=(
            "SUID binary whose name appears in GTFOBins. Validate that it "
            "can actually spawn a shell or write files as root.",
        ),
    ),
    "NEXUS-SGID-001": KnowledgeEntry(
        cwe=("CWE-269",),
        attack=("T1548.001",),
        references=("https://cwe.mitre.org/data/definitions/269.html",),
    ),

    # ----- Sudo -----
    "NEXUS-SUDO-001": KnowledgeEntry(
        cwe=("CWE-269", "CWE-522"),
        attack=("T1548.003",),
        references=(
            "https://www.sudo.ws/docs/man/sudoers.man/",
            "https://cwe.mitre.org/data/definitions/269.html",
            "https://attack.mitre.org/techniques/T1548/003/",
        ),
        notes=(
            "NOPASSWD removes the last authentication barrier for the "
            "allowed command(s). Combined with a GTFOBins binary, this "
            "is often a direct root shell.",
        ),
    ),
    "NEXUS-SUDO-002": KnowledgeEntry(
        cwe=("CWE-269", "CWE-78"),
        attack=("T1548.003",),
        references=(
            "https://gtfobins.github.io",
            "https://attack.mitre.org/techniques/T1548/003/",
        ),
        notes=(
            "Sudo entry allows a binary that is dangerous (editor, "
            "interpreter, file copy) or uses a wildcard. Both can lead "
            "to arbitrary command execution as root.",
        ),
    ),

    # ----- Capabilities -----
    "NEXUS-CAP-001": KnowledgeEntry(
        cwe=("CWE-269", "CWE-250"),
        attack=("T1548",),
        references=(
            "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            "https://cwe.mitre.org/data/definitions/269.html",
        ),
        notes=(
            "File capabilities like cap_setuid or cap_sys_admin provide "
            "root-equivalent power without setting the SUID bit, and are "
            "often overlooked by admins.",
        ),
    ),

    # ----- Cron -----
    "NEXUS-CRON-001": KnowledgeEntry(
        cwe=("CWE-732",),
        attack=("T1053.003",),
        references=(
            "https://cwe.mitre.org/data/definitions/732.html",
            "https://attack.mitre.org/techniques/T1053/003/",
        ),
        notes=(
            "If the cron job is executed as root and the script is "
            "writable by the attacker, the attacker gains root code "
            "execution on the next scheduled run.",
        ),
    ),
    "NEXUS-CRON-002": KnowledgeEntry(
        cwe=("CWE-426",),
        attack=("T1574.007",),
        references=(
            "https://cwe.mitre.org/data/definitions/426.html",
            "https://attack.mitre.org/techniques/T1574/007/",
        ),
    ),

    # ----- Writable / PATH -----
    "NEXUS-WRITE-001": KnowledgeEntry(
        cwe=("CWE-732", "CWE-284"),
        attack=("T1222", "T1548"),
        references=(
            "https://cwe.mitre.org/data/definitions/732.html",
            "https://attack.mitre.org/techniques/T1222/",
        ),
    ),
    "NEXUS-PATH-001": KnowledgeEntry(
        cwe=("CWE-426",),
        attack=("T1574.007",),
        references=(
            "https://cwe.mitre.org/data/definitions/426.html",
            "https://attack.mitre.org/techniques/T1574/007/",
        ),
    ),

    # ----- Kernel -----
    "NEXUS-KERN-001": KnowledgeEntry(
        cwe=("CWE-1104",),
        attack=("T1068",),
        references=(
            "https://www.cve.org",
            "https://attack.mitre.org/techniques/T1068/",
        ),
        notes=(
            "Kernel version heuristics only. Cross-reference with public "
            "CVE databases before drawing conclusions.",
        ),
    ),

    # ----- Containers -----
    "NEXUS-DOCKER-001": KnowledgeEntry(
        cwe=("CWE-269", "CWE-284"),
        attack=("T1610", "T1611"),
        references=(
            "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security",
            "https://attack.mitre.org/techniques/T1610/",
            "https://attack.mitre.org/techniques/T1611/",
        ),
        notes=(
            "Accessible docker socket allows mounting the host filesystem "
            "into a container and reading or writing any file as root.",
        ),
    ),

    # ----- Groups -----
    "NEXUS-GROUP-001": KnowledgeEntry(
        cwe=("CWE-269", "CWE-284"),
        attack=("T1078.003",),
        references=(
            "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
            "https://attack.mitre.org/techniques/T1078/003/",
        ),
    ),

    # ----- SSH -----
    "NEXUS-SSH-001": KnowledgeEntry(
        cwe=("CWE-522", "CWE-732"),
        attack=("T1552.004",),
        references=(
            "https://cwe.mitre.org/data/definitions/522.html",
            "https://attack.mitre.org/techniques/T1552/004/",
        ),
    ),

    # ----- Correlation rules -----
    "NEXUS-CORR-DOCKER-001": KnowledgeEntry(
        cwe=("CWE-269",),
        attack=("T1610", "T1611", "T1078.003"),
        references=(
            "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security",
            "https://attack.mitre.org/techniques/T1610/",
        ),
    ),
    "NEXUS-CORR-LXD-001": KnowledgeEntry(
        cwe=("CWE-269",),
        attack=("T1610", "T1078.003"),
        references=(
            "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/lxd-privilege-escalation",
            "https://attack.mitre.org/techniques/T1610/",
        ),
    ),
    "NEXUS-CORR-SSH-001": KnowledgeEntry(
        cwe=("CWE-522",),
        attack=("T1552.004", "T1021.004"),
        references=(
            "https://attack.mitre.org/techniques/T1552/004/",
            "https://attack.mitre.org/techniques/T1021/004/",
        ),
    ),
    "NEXUS-SYSD-001": KnowledgeEntry(
        cwe=("CWE-732", "CWE-269"),
        attack=("T1543.002",),
        references=(
            "https://attack.mitre.org/techniques/T1543/002/",
            "https://cwe.mitre.org/data/definitions/732.html",
        ),
        notes=(
            "Writable systemd unit executed as root allows arbitrary code "
            "execution after daemon-reload and service restart.",
        ),
    ),
}


def get_knowledge(rule_id: str) -> KnowledgeEntry | None:
    """Return the knowledge entry for a rule id, or None."""
    return KNOWLEDGE.get(rule_id)
