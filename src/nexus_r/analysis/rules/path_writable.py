"""Detect writable directories in PATH.

A writable directory in $PATH lets us drop a binary that shadows a
legitimate one. When a privileged script calls that binary by name,
it runs our version as root.

Directories owned by the current user are skipped: if we own the
directory, we can already write to it legitimately, so it is not a
privilege escalation vector from our perspective.
"""

from __future__ import annotations

import os

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType


class PathWritableRule(Rule):
    """Flags writable directories present in $PATH, excluding our own."""

    id = "NEXUS-PATH-001"
    title = "Writable PATH entry"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        my_uid = os.getuid()
        results: list[RuleResult] = []

        for ev in store.by_type(EvidenceType.OTHER):
            if ev.data.get("kind") != "path_entry":
                continue
            if not ev.data.get("is_dir"):
                continue
            if not (ev.data.get("world_writable") or ev.data.get("group_writable")):
                continue

            # Skip our own directories
            if ev.data.get("owner_uid") == my_uid:
                continue

            path = ev.data.get("path", "")
            mode = ev.data.get("mode", "?")

            results.append(
                RuleResult(
                    rule_id=self.id,
                    title=f"Writable directory in PATH: {path}",
                    description=(
                        f"Directory '{path}' (mode {mode}) is in $PATH and "
                        "writable by our user or group, and is not owned by "
                        "us. May allow command hijacking."
                    ),
                    category="privilege-escalation",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence_ids=[ev.id],
                    validation_steps=[
                        f"Verify: ls -ld {path}",
                        "Identify privileged scripts that call binaries "
                        "by name and are run with elevated privileges.",
                    ],
                    references=["MITRE ATT&CK T1574.007"],
                    tags=["path", "writable"],
                )
            )
        return results
