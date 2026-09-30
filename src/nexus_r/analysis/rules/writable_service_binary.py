"""Detect writable systemd unit files.

A unit file writable by the current user can be edited to run
arbitrary commands as root after `systemctl daemon-reload` and a
service restart.
"""

from __future__ import annotations

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType


class WritableSystemdUnitRule(Rule):
    """Flags writable systemd unit files."""

    id = "NEXUS-SYSD-001"
    title = "Writable systemd unit file"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.SYSTEMD):
            if not (ev.data.get("world_writable") or ev.data.get("group_writable")):
                continue
            path = ev.data.get("path", "")
            mode = ev.data.get("mode", "?")
            results.append(
                RuleResult(
                    rule_id=self.id,
                    title=f"Writable systemd unit: {path}",
                    description=(
                        f"Unit file '{path}' (mode {mode}) is writable by "
                        "our user or group. If the unit runs as root, "
                        "modifying it allows root code execution."
                    ),
                    category="privilege-escalation",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence_ids=[ev.id],
                    validation_steps=[
                        f"Verify: ls -la {path}",
                        f"Read: cat {path}",
                        "Check for 'User=root' or absence of 'User='.",
                        "Reload after edit: systemctl daemon-reload",
                        "Do NOT modify on production.",
                    ],
                    references=["MITRE ATT&CK T1543.002"],
                    tags=["systemd", "writable"],
                )
            )
        return results
