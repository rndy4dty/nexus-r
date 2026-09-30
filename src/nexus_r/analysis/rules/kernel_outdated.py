"""Detect old kernel versions (heuristic)."""

from __future__ import annotations

import re

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType

VERSION_RE = re.compile(r"^(\d+)\.(\d+)")

# Very old mainline thresholds; heuristic only.
MIN_MAJOR = 4
MIN_MINOR = 15


class KernelOutdatedRule(Rule):
    """Flags kernel versions below a heuristic threshold."""

    id = "NEXUS-KERN-001"
    title = "Kernel version heuristic"
    severity = Severity.MEDIUM
    confidence = Confidence.LOW

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.SYSTEM):
            data = ev.data or {}
            release = data.get("kernel_release") or ""
            m = VERSION_RE.match(release)
            if not m:
                continue
            major, minor = int(m.group(1)), int(m.group(2))
            if (major, minor) >= (MIN_MAJOR, MIN_MINOR):
                continue

            results.append(
                RuleResult(
                    rule_id=self.id,
                    title=f"Old kernel release: {release}",
                    description=(
                        f"Kernel {release} is older than heuristic threshold "
                        f"{MIN_MAJOR}.{MIN_MINOR}. May include known local "
                        "privilege-escalation CVEs."
                    ),
                    category="kernel",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    evidence_ids=[ev.id],
                    validation_steps=[
                        f"Check uname -r: {release}",
                        "Cross-reference with local public CVE databases.",
                        "Do NOT assume exploitability. Validate in a lab.",
                    ],
                    references=[
                        "https://www.cve.org",
                        "MITRE ATT&CK T1068",
                    ],
                    tags=["kernel", "outdated"],
                )
            )
        return results
