"""Template-based hypothesis generation.

This is the offline fallback: it does not call any LLM. It reads the
report, groups findings by category, and produces one hypothesis per
category with a plain-language explanation and validation steps.

Template hypotheses are always available, so the analysis pipeline is
never dependent on an external service.
"""

from __future__ import annotations

from typing import Any

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.ai.model import Hypothesis, HypothesisMode, HypothesisStatus

# Per-category analyst notes. Keep them short and factual.
CATEGORY_NOTES: dict[str, str] = {
    "privilege-escalation": (
        "Findings in this category may allow a local user to gain "
        "additional privileges. Validate each one in an isolated lab "
        "before drawing conclusions, since environment details matter."
    ),
    "container-escape": (
        "Findings in this category may allow escaping a container and "
        "gaining control of the host. Confirm group membership and "
        "socket access before testing."
    ),
    "credential-exposure": (
        "Readable credentials may enable lateral movement. Do NOT "
        "exfiltrate or copy contents. Confirm ownership and authorized "
        "users, then report."
    ),
    "lateral-movement": (
        "This path enables movement to other hosts. Cross-reference "
        "with your assessment scope before testing."
    ),
    "vulnerable-package": (
        "Installed package is below a known-vulnerable version. "
        "Cross-reference with the distribution advisory. Version "
        "matching is best-effort; do not assume exploitability."
    ),
    "kernel": (
        "Kernel version heuristic. Only a small subset of kernel CVEs "
        "are locally exploitable. Cross-reference with a CVE database "
        "and validate in a lab."
    ),
    "enumeration": (
        "Informational finding. No immediate action required, but "
        "useful for context."
    ),
}

CATEGORY_VALIDATION: dict[str, list[str]] = {
    "privilege-escalation": [
        "Read the finding description and its evidence references.",
        "Reproduce the condition inside an isolated lab container.",
        "Record the exact commands, output, and outcome.",
    ],
    "container-escape": [
        "Verify the current user's groups: id",
        "Verify socket access: ls -la /var/run/docker.sock",
        "Do NOT run mount or privileged containers on production.",
    ],
    "credential-exposure": [
        "Verify permissions: ls -la <path>",
        "Do NOT copy or exfiltrate credentials.",
        "Report owner and authorized user.",
    ],
    "lateral-movement": [
        "Cross-reference with your authorized scope.",
        "Confirm with the asset owner before any remote test.",
    ],
    "vulnerable-package": [
        "Check the exact installed version: dpkg -l <pkg>",
        "Consult the distribution security advisory.",
        "Do NOT run public exploits on production systems.",
    ],
    "kernel": [
        "Check the exact kernel release: uname -r",
        "Cross-reference with a CVE database.",
        "Only attempt in a lab with snapshots.",
    ],
    "enumeration": [
        "No validation required. Informational.",
    ],
}


def _severity_for_group(findings: list[dict[str, Any]]) -> Severity:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    best = "info"
    for f in findings:
        sev = f.get("severity", "info")
        if order.get(sev, 9) < order.get(best, 9):
            best = sev
    return Severity(best)


def _confidence_for_group(findings: list[dict[str, Any]]) -> Confidence:
    order = {"high": 0, "medium": 1, "low": 2}
    best = "low"
    for f in findings:
        c = f.get("confidence", "low")
        if order.get(c, 9) < order.get(best, 9):
            best = c
    return Confidence(best)


class TemplateAnalyzer:
    """Generates template hypotheses from a report."""

    mode = HypothesisMode.TEMPLATE
    model = "template"

    def analyze(self, report: dict[str, Any]) -> list[Hypothesis]:
        findings = report.get("findings", [])
        if not findings:
            return []

        # Group by category
        grouped: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            cat = f.get("category", "other")
            grouped.setdefault(cat, []).append(f)

        hypotheses: list[Hypothesis] = []
        for i, (cat, items) in enumerate(sorted(grouped.items()), start=1):
            severity = _severity_for_group(items)
            confidence = _confidence_for_group(items)
            finding_ids = [f.get("id", "") for f in items if f.get("id")]
            note = CATEGORY_NOTES.get(
                cat,
                "Review the findings in this category individually.",
            )
            steps = CATEGORY_VALIDATION.get(
                cat,
                ["Review the finding description and evidence."],
            )
            hypotheses.append(
                Hypothesis(
                    id=f"H-{i:04d}",
                    finding_ids=tuple(finding_ids),
                    mode=self.mode,
                    model=self.model,
                    title=f"{cat}: {len(items)} finding(s)",
                    narrative=note,
                    severity=severity,
                    confidence=confidence,
                    status=HypothesisStatus.NEEDS_REVIEW,
                    validation_steps=tuple(steps),
                    references=(),
                    tags=("template", cat),
                )
            )
        return hypotheses
