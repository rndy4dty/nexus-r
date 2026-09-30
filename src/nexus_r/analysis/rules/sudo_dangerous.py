"""Detect dangerous sudo commands / wildcards / ALL."""

from __future__ import annotations

import re

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType

DANGEROUS_BINARIES = {
    "vi", "vim", "nano", "less", "more", "man",
    "find", "awk", "gawk", "sed", "perl",
    "python", "python2", "python3", "ruby", "node", "php", "lua",
    "bash", "sh", "dash", "zsh", "env",
    "tar", "zip", "unzip", "cp", "mv", "dd", "tee", "install",
    "chmod", "chown", "chattr", "mount", "umount",
    "docker", "podman",
    "systemctl", "journalctl", "service",
    "gdb", "strace", "ltrace",
    "nmap", "nc", "netcat", "socat",
}

ALL_TOKEN_RE = re.compile(r"(?:^|\s)ALL(?:\s|$)")


def _extract_command(entry: str) -> str:
    """Extract the command part from a sudoers entry.

    Format is roughly:

        user host=(runas) [tags:] command

    The (runas) part may contain ':' (e.g. ``ALL:ALL``), so we strip the
    first parenthesized group before looking for the command separator.
    """
    # Remove the (runas) or (user:group) group
    without_runas = re.sub(r"\([^)]*\)", "()", entry, count=1)

    # Tags like NOPASSWD: are separated by ':' from the command
    if ":" in without_runas:
        return without_runas.rsplit(":", 1)[1].strip()

    # No tags: command is after the "= "
    if "= " in without_runas:
        return without_runas.split("= ", 1)[1].strip()

    return without_runas.strip()


class SudoDangerousRule(Rule):
    """Flags sudoers entries that allow dangerous commands or wildcards."""

    id = "NEXUS-SUDO-002"
    title = "Dangerous sudo entry"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.SUDO):
            if not ev.data.get("readable", True):
                continue
            entry = ev.data.get("entry", "").strip()
            if not entry or entry.startswith("Defaults"):
                continue

            cmd = _extract_command(entry)
            if not cmd:
                continue

            reasons: list[str] = []

            if "*" in cmd:
                reasons.append("wildcard argument")
            if ALL_TOKEN_RE.search(cmd):
                reasons.append("ALL command")

            for binary in DANGEROUS_BINARIES:
                if re.search(rf"(?:^|[\s/]){re.escape(binary)}(?:\s|$)", cmd):
                    reasons.append(f"dangerous binary: {binary}")
                    break

            if not reasons:
                continue

            path = ev.data.get("path", "")
            lineno = ev.data.get("line", 0)

            results.append(
                RuleResult(
                    rule_id=self.id,
                    title="Sudo entry may allow privesc",
                    description=(
                        f"Sudoers entry in {path}:{lineno} has: "
                        f"{', '.join(reasons)}. Entry: {entry}"
                    ),
                    category="privilege-escalation",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    evidence_ids=[ev.id],
                    validation_steps=[
                        "Review the sudoers entry.",
                        "Check if the allowed binary can spawn a shell, edit "
                        "files, or read sensitive data as root.",
                        "Cross-reference the binary with GTFOBins.",
                        "Do NOT test directly on production.",
                    ],
                    references=[
                        "https://gtfobins.github.io",
                        "MITRE ATT&CK T1548.003",
                    ],
                    tags=["sudo", "dangerous"],
                )
            )
        return results
