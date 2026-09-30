"""Detect potential PATH hijack opportunities in cron entries.

A cron entry that calls a command by name (no absolute path) can be
hijacked if any directory earlier in PATH is writable by our user.
This rule needs corroborating evidence: a writable PATH directory
(provided by the environment collector).

Two crontab formats are handled:

- system format (/etc/crontab, /etc/cron.d/*):
      m h dom mon dow USER command...
  -> command starts at index 6.

- user format (/var/spool/cron/crontabs/*):
      m h dom mon dow command...
  -> command starts at index 5.

Shell builtins (cd, test, echo, ...) are skipped because they are not
resolved via PATH.
"""

from __future__ import annotations

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType

# Shell builtins that do NOT get resolved via PATH
SHELL_BUILTINS: frozenset[str] = frozenset({
    "cd", "test", "[", "]", "echo", "exit", "export", "read", "set",
    "shift", "unset", "eval", "exec", "local", "return", "readonly",
    "declare", "typeset", "let", "pwd", "times", "trap", "type",
    "ulimit", "umask", "wait", "continue", "break", ":", ".",
    "alias", "unalias", "bg", "fg", "jobs", "kill", "suspend",
    "getopts", "hash", "help", "history", "fc",
    "true", "false", "{", "}", "(", ")", "||", "&&", ";",
})


def _extract_command(entry: str, path: str) -> str | None:
    """Return the command portion of a cron entry, or None if unknown."""
    parts = entry.split()
    if len(parts) < 6:
        return None

    if path == "/etc/crontab" or path.startswith("/etc/cron.d/"):
        if len(parts) < 7:
            return None
        cmd_parts = parts[6:]
    else:
        cmd_parts = parts[5:]

    return " ".join(cmd_parts) if cmd_parts else None


class CronPathHijackRule(Rule):
    """Flags cron entries calling bare commands while a writable PATH exists."""

    id = "NEXUS-CRON-002"
    title = "Cron PATH hijack candidate"
    severity = Severity.MEDIUM
    confidence = Confidence.LOW

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        writable_dirs: list[str] = []
        for ev in store.by_type(EvidenceType.OTHER):
            if ev.data.get("kind") != "path_entry":
                continue
            if not ev.data.get("is_dir"):
                continue
            if ev.data.get("world_writable") or ev.data.get("group_writable"):
                writable_dirs.append(ev.data.get("path", ""))

        if not writable_dirs:
            return []

        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.CRON):
            if ev.data.get("kind") != "entry":
                continue
            entry = ev.data.get("entry", "")
            path = ev.data.get("path", "")
            if not entry or not path:
                continue

            command_line = _extract_command(entry, path)
            if not command_line:
                continue

            binary = command_line.split()[0] if command_line.split() else ""
            if not binary:
                continue

            # Skip shell builtins
            if binary in SHELL_BUILTINS:
                continue

            # Skip absolute paths (safe)
            if binary.startswith("/"):
                continue

            results.append(
                RuleResult(
                    rule_id=self.id,
                    title=f"Cron PATH hijack candidate: {binary}",
                    description=(
                        f"Cron entry calls '{binary}' without absolute path. "
                        f"Writable directories in PATH: {', '.join(writable_dirs)}. "
                        f"Entry: {entry}"
                    ),
                    category="privilege-escalation",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    evidence_ids=[ev.id],
                    validation_steps=[
                        f"Read: {path}",
                        f"Inspect writable PATH dirs: {writable_dirs}",
                        "Confirm whether the command is resolved from a "
                        "writable path.",
                    ],
                    references=["MITRE ATT&CK T1574.007"],
                    tags=["cron", "path-hijack"],
                )
            )
        return results
