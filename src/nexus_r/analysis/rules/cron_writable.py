"""Detect writable cron scripts.

A cron script that is writable by our user (owner-writable,
group-writable to one of our groups, or world-writable) is a privesc
candidate if the cron entry runs as root.
"""

from __future__ import annotations

import os
from pathlib import Path

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType

MY_UID = os.getuid()
MY_GIDS = {os.getgid(), *os.getgroups()}


class CronWritableRule(Rule):
    """Flags cron scripts that are writable by the current user."""

    id = "NEXUS-CRON-001"
    title = "Writable cron script"
    severity = Severity.HIGH
    confidence = Confidence.HIGH

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.CRON):
            if ev.data.get("kind") != "script":
                continue
            path_str = ev.data.get("path", "")
            if not path_str:
                continue

            try:
                st = os.stat(path_str)
            except (OSError, PermissionError):
                continue

            reason = self._writable_reason(st, MY_UID, MY_GIDS)
            if not reason:
                continue

            results.append(
                RuleResult(
                    rule_id=self.id,
                    title=f"Writable cron script: {path_str}",
                    description=(
                        f"Cron script '{path_str}' is {reason}. "
                        "If this cron runs as root, it may allow "
                        "privilege escalation."
                    ),
                    category="privilege-escalation",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence_ids=[ev.id],
                    validation_steps=[
                        f"Inspect: ls -la {path_str}",
                        f"Read: cat {path_str}",
                        "Check which user runs this cron (look at /etc/crontab).",
                        "Modify only in a controlled lab environment.",
                    ],
                    references=["MITRE ATT&CK T1053.003"],
                    tags=["cron", "writable"],
                )
            )
        return results

    @staticmethod
    def _writable_reason(st: os.stat_result, uid: int, gids: set[int]) -> str | None:
        if st.st_mode & 0o002:
            return "world-writable"
        if st.st_gid in gids and (st.st_mode & 0o020):
            return "group-writable"
        if st.st_uid == uid and (st.st_mode & 0o200):
            return "owner-writable"
        return None


# Suppress unused import warning in case Path is not used in future edits
_ = Path
