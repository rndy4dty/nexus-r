"""Correlate readable SSH private keys with lateral movement.

A readable private SSH key is a credential exposure. On its own it is
a finding; combined with the fact that SSH clients are typically
available on the host, it becomes a lateral-movement attack path:
the analyst can attempt to authenticate to other hosts using the key.

This is NOT a privilege escalation to root on the current host. It is
a lateral movement path. The target is therefore "remote-host", not
"root".
"""

from __future__ import annotations

from nexus_r.analysis.correlation.path import AttackPathStatus
from nexus_r.analysis.correlation.rule import CorrelationResult, CorrelationRule
from nexus_r.analysis.finding import Confidence, Finding, Severity
from nexus_r.evidence import EvidenceStore


class SshKeyLateralCorrelation(CorrelationRule):
    """Correlates readable SSH private keys with lateral movement."""

    id = "NEXUS-CORR-SSH-001"
    title = "Readable SSH key => lateral movement"

    def evaluate(
        self, findings: list[Finding], store: EvidenceStore
    ) -> list[CorrelationResult]:
        results: list[CorrelationResult] = []
        for f in findings:
            if f.rule_id != "NEXUS-SSH-001":
                continue
            if "private ssh key" not in f.title.lower():
                continue

            results.append(
                CorrelationResult(
                    rule_id=self.id,
                    title="Readable private SSH key enables lateral movement",
                    narrative=(
                        f"A private SSH key is readable by the current user "
                        f"({f.title}). If this key is authorized on other "
                        "hosts, the user can authenticate to them without a "
                        "password. This is a credential-exposure path, not "
                        "a privilege escalation on the current host."
                    ),
                    category="lateral-movement",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    finding_ids=[f.id],
                    entry_point="current-host",
                    target="remote-host",
                    status=AttackPathStatus.HYPOTHESIS,
                    validation_steps=[
                        "Identify the key: ls -la ~/.ssh",
                        "Check for known_hosts entries: cat ~/.ssh/known_hosts",
                        "Check SSH config: cat ~/.ssh/config",
                        "Do NOT attempt authentication to systems you "
                        "do not have written authorization to test.",
                    ],
                    references=[
                        "MITRE ATT&CK T1552.004",
                        "MITRE ATT&CK T1021.004",
                    ],
                    tags=["ssh", "credential", "lateral-movement", "attack-path"],
                )
            )
        return results
