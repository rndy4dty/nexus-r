"""Correlate docker group membership with docker socket access.

Two findings:

- NEXUS-GROUP-001: user in group 'docker'
- NEXUS-DOCKER-001: docker.sock accessible

Together they enable a concrete privilege escalation: the user can
talk to the Docker daemon, mount the host filesystem into a container
and obtain root on the host.

This correlation rule does NOT test exploitability - it only notes
that the two findings together form a plausible attack path.
"""

from __future__ import annotations

from nexus_r.analysis.correlation.path import AttackPathStatus
from nexus_r.analysis.correlation.rule import CorrelationResult, CorrelationRule
from nexus_r.analysis.finding import Confidence, Finding, Severity
from nexus_r.evidence import EvidenceStore


class DockerGroupSocketCorrelation(CorrelationRule):
    """Correlates 'docker' group membership with docker socket presence."""

    id = "NEXUS-CORR-DOCKER-001"
    title = "Docker group + socket => root on host"

    def evaluate(
        self, findings: list[Finding], store: EvidenceStore
    ) -> list[CorrelationResult]:
        docker_group_findings = [
            f
            for f in findings
            if f.rule_id == "NEXUS-GROUP-001"
            and "docker" in f.title.lower()
            and "members" in f.title.lower()
        ]
        docker_socket_findings = [
            f
            for f in findings
            if f.rule_id == "NEXUS-DOCKER-001"
            and "docker.sock" in f.title.lower()
        ]

        if not docker_group_findings or not docker_socket_findings:
            return []

        results: list[CorrelationResult] = []
        for group_f in docker_group_findings:
            for socket_f in docker_socket_findings:
                finding_ids = sorted({group_f.id, socket_f.id})
                results.append(
                    CorrelationResult(
                        rule_id=self.id,
                        title="User in 'docker' group can escalate to root via docker.sock",
                        narrative=(
                            "The current user belongs to the 'docker' group, "
                            "and the Docker daemon socket is accessible at "
                            f"{socket_f.title}. Because the Docker daemon "
                            "runs as root, this user can start a container "
                            "with the host root filesystem mounted, "
                            "effectively obtaining root on the host."
                        ),
                        category="privilege-escalation",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        finding_ids=finding_ids,
                        entry_point="user",
                        target="root",
                        status=AttackPathStatus.PLAUSIBLE,
                        validation_steps=[
                            "Verify group membership: id",
                            "Verify socket access: docker ps",
                            "In a LAB only: test with a read-only mount:",
                            "  docker run --rm -it -v /:/host alpine chroot /host",
                            "Do NOT run this on production systems.",
                        ],
                        references=[
                            "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security",
                            "MITRE ATT&CK T1610",
                            "MITRE ATT&CK T1078.003",
                        ],
                        tags=["docker", "privesc", "attack-path"],
                    )
                )
        return results
