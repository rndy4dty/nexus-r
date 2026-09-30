"""Detect NOPASSWD in sudoers."""

from __future__ import annotations

import re

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType

NOPASSWD_RE = re.compile(r"NOPASSWD", re.IGNORECASE)


class SudoNopasswdRule(Rule):
    """Flags sudoers entries that allow running commands without password."""

    id = "NEXUS-SUDO-001"
    title = "Sudo NOPASSWD entry"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.SUDO):
            if not ev.data.get("readable", True):
                continue
            entry = ev.data.get("entry", "")
            if not NOPASSWD_RE.search(entry):
                continue

            path = ev.data.get("path", "")
            lineno = ev.data.get("line", 0)

            results.append(
                RuleResult(
                    rule_id=self.id,
                    title="Sudo NOPASSWD entry detected",
                    description=(
                        f"Sudoers entry in {path}:{lineno} contains NOPASSWD. "
                        f"Entry: {entry}"
                    ),
                    category="privilege-escalation",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence_ids=[ev.id],
                    validation_steps=[
                        f"Review the entry: sudo -l",
                        f"Inspect: {path} (line {lineno})",
                        "Check whether the allowed command can spawn a shell "
                        "or read/write files as root.",
                        "Cross-reference the allowed binary with GTFOBins.",
                    ],
                    references=[
                        "https://www.sudo.ws/docs/man/sudoers.man/",
                        "MITRE ATT&CK T1548.003",
                    ],
                    tags=["sudo", "nopasswd"],
                )
            )
        return results
