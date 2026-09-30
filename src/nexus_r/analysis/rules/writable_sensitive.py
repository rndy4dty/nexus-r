"""Detect writable sensitive files.

A sensitive file (e.g. /etc/passwd) that is world-writable or
group-writable by one of our groups is a direct privilege escalation
path.
"""

from __future__ import annotations

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType

CRITICAL_PATHS: dict[str, Severity] = {
    "/etc/passwd": Severity.CRITICAL,
    "/etc/shadow": Severity.CRITICAL,
    "/etc/gshadow": Severity.CRITICAL,
    "/etc/sudoers": Severity.CRITICAL,
    "/etc/sudoers.d": Severity.CRITICAL,
    "/root/.ssh": Severity.CRITICAL,
    "/etc/ssh/sshd_config": Severity.HIGH,
    "/etc/crontab": Severity.HIGH,
    "/etc/cron.d": Severity.HIGH,
    "/etc/group": Severity.HIGH,
    "/etc/systemd/system": Severity.HIGH,
    "/lib/systemd/system": Severity.HIGH,
    "/usr/lib/systemd/system": Severity.HIGH,
    "/root": Severity.HIGH,
    "/etc/hosts": Severity.MEDIUM,
}


class WritableSensitiveRule(Rule):
    """Flags sensitive paths that are writable by our user or groups."""

    id = "NEXUS-WRITE-001"
    title = "Writable sensitive file"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.WRITABLE):
            path = ev.data.get("path", "")
            if path not in CRITICAL_PATHS:
                continue
            if not (ev.data.get("world_writable") or ev.data.get("group_writable")):
                continue

            sev = CRITICAL_PATHS[path]
            mode = ev.data.get("mode", "?")

            results.append(
                RuleResult(
                    rule_id=self.id,
                    title=f"Writable sensitive path: {path}",
                    description=(
                        f"'{path}' has mode {mode} and is writable by our "
                        "user or one of our groups. This may allow direct "
                        "privilege escalation."
                    ),
                    category="privilege-escalation",
                    severity=sev,
                    confidence=Confidence.HIGH,
                    evidence_ids=[ev.id],
                    validation_steps=[
                        f"Verify: ls -la {path}",
                        "Confirm write access from the current user.",
                        "Do NOT modify in production. Test in a lab only.",
                    ],
                    references=[
                        "MITRE ATT&CK T1222",
                        "MITRE ATT&CK T1548",
                    ],
                    tags=["writable", "sensitive"],
                )
            )
        return results
