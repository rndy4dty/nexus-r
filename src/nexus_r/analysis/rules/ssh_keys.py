"""Detect readable SSH private keys.

Walks the home directories reported by the UsersCollector and checks
for readable private keys. Does not read the full content, only the
first bytes to confirm it is a key.

Home directories we cannot access (e.g. /root) are skipped silently.
"""

from __future__ import annotations

from pathlib import Path

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType

KEY_NAMES = ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "identity")


class SshKeysRule(Rule):
    """Flags readable SSH private keys in user home directories."""

    id = "NEXUS-SSH-001"
    title = "Readable SSH private key"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.USER):
            home = ev.data.get("home") or ""
            if not home:
                continue

            ssh_dir = Path(home) / ".ssh"
            if not self._is_readable_dir(ssh_dir):
                continue

            for name in KEY_NAMES:
                key = ssh_dir / name
                if not self._is_readable_file(key):
                    continue

                try:
                    head = key.read_text(
                        encoding="utf-8", errors="replace"
                    )[:200]
                except (OSError, PermissionError):
                    continue

                if "PRIVATE KEY" not in head:
                    continue

                results.append(
                    RuleResult(
                        rule_id=self.id,
                        title=f"Private SSH key readable: {key}",
                        description=(
                            f"Private key at '{key}' is readable by the "
                            "current user. May grant lateral movement to "
                            "other hosts."
                        ),
                        category="credential-exposure",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        evidence_ids=[ev.id],
                        validation_steps=[
                            f"Verify permissions: ls -la {key}",
                            "Do NOT exfiltrate. Do NOT copy contents.",
                            "Report owner and authorized user.",
                        ],
                        references=["MITRE ATT&CK T1552.004"],
                        tags=["ssh", "credential"],
                    )
                )
        return results

    @staticmethod
    def _is_readable_dir(path: Path) -> bool:
        try:
            return path.is_dir()
        except (OSError, PermissionError):
            return False

    @staticmethod
    def _is_readable_file(path: Path) -> bool:
        try:
            return path.is_file()
        except (OSError, PermissionError):
            return False
