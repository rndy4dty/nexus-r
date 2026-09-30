"""Detect accessible Docker socket."""

from __future__ import annotations

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType


class DockerSocketRule(Rule):
    """Flags Docker socket presence as a container-escape candidate."""

    id = "NEXUS-DOCKER-001"
    title = "Docker socket accessible"
    severity = Severity.CRITICAL
    confidence = Confidence.MEDIUM

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.DOCKER):
            if ev.data.get("kind") != "socket":
                continue
            path = ev.data.get("path", "")
            if not path:
                continue

            results.append(
                RuleResult(
                    rule_id=self.id,
                    title=f"Docker socket present: {path}",
                    description=(
                        f"Docker socket '{path}' exists. If readable by the "
                        "current user, it can be used to mount the host "
                        "filesystem and escalate to root on the host."
                    ),
                    category="container-escape",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    evidence_ids=[ev.id],
                    validation_steps=[
                        f"Check: ls -la {path}",
                        "Check current user groups: id",
                        "If you have access: docker ps (read-only listing)",
                        "Do NOT run docker run -v /:/host on production.",
                    ],
                    references=[
                        "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security",
                        "MITRE ATT&CK T1610",
                    ],
                    tags=["docker", "socket"],
                )
            )
        return results
