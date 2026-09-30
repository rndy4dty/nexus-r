"""Detect users in dangerous groups.

Some Linux groups grant effective root-equivalent privileges:

- docker / podman: access to the daemon socket -> host mount -> root
- lxd / lxc: container management -> root on host
- disk: raw block device access -> read/write any file
- sudo / wheel / sudoers: explicit sudo privileges
- adm / shadow: read sensitive logs / password hashes
- staff: often has /usr/local write access

Group membership alone is not a vulnerability - it depends on the
environment. This rule therefore reports MEDIUM confidence.
"""

from __future__ import annotations

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType

DANGEROUS_GROUPS: dict[str, Severity] = {
    "docker": Severity.CRITICAL,
    "podman": Severity.CRITICAL,
    "lxd": Severity.CRITICAL,
    "lxc": Severity.HIGH,
    "disk": Severity.HIGH,
    "sudo": Severity.HIGH,
    "wheel": Severity.HIGH,
    "sudoers": Severity.HIGH,
    "shadow": Severity.HIGH,
    "adm": Severity.MEDIUM,
    "staff": Severity.MEDIUM,
    "audio": Severity.LOW,
    "video": Severity.LOW,
}


class DangerousGroupsRule(Rule):
    """Flags groups with potentially dangerous members."""

    id = "NEXUS-GROUP-001"
    title = "Dangerous group has members"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.GROUP):
            name = ev.data.get("name", "")
            if name not in DANGEROUS_GROUPS:
                continue

            members = ev.data.get("members") or []
            if not members:
                continue

            sev = DANGEROUS_GROUPS[name]
            results.append(
                RuleResult(
                    rule_id=self.id,
                    title=f"Group '{name}' has members: {', '.join(members)}",
                    description=(
                        f"Membership in '{name}' can grant effective "
                        "privileges equivalent to or approaching root, "
                        "depending on the environment."
                    ),
                    category="privilege-escalation",
                    severity=sev,
                    confidence=Confidence.MEDIUM,
                    evidence_ids=[ev.id],
                    validation_steps=[
                        f"Check: getent group {name}",
                        "Determine whether the current user is a member.",
                        f"Assess whether the group grants root-equivalent "
                        "access on this system.",
                    ],
                    references=[
                        "https://book.hacktricks.xyz/linux-hardening/privilege-escalation",
                        "MITRE ATT&CK T1078.003",
                    ],
                    tags=["group", "membership", name],
                )
            )
        return results
