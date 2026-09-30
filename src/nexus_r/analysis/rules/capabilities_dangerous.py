"""Detect dangerous Linux capabilities on files."""

from __future__ import annotations

from nexus_r.analysis.finding import Confidence, Severity
from nexus_r.analysis.rule import Rule, RuleResult
from nexus_r.evidence import EvidenceStore, EvidenceType

DANGEROUS_CAPS: dict[str, Severity] = {
    "cap_setuid": Severity.CRITICAL,
    "cap_setgid": Severity.HIGH,
    "cap_sys_admin": Severity.CRITICAL,
    "cap_sys_ptrace": Severity.HIGH,
    "cap_sys_module": Severity.CRITICAL,
    "cap_dac_read_search": Severity.HIGH,
    "cap_dac_override": Severity.HIGH,
    "cap_sys_chroot": Severity.MEDIUM,
    "cap_chown": Severity.MEDIUM,
    "cap_fowner": Severity.MEDIUM,
    "cap_net_admin": Severity.MEDIUM,
    "cap_sys_rawio": Severity.HIGH,
    "cap_lease": Severity.MEDIUM,
    "cap_sys_time": Severity.MEDIUM,
}


class CapabilitiesDangerousRule(Rule):
    """Flags files with dangerous capabilities."""

    id = "NEXUS-CAP-001"
    title = "Dangerous Linux capability"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM

    def evaluate(self, store: EvidenceStore) -> list[RuleResult]:
        results: list[RuleResult] = []
        for ev in store.by_type(EvidenceType.CAPABILITY):
            if ev.data.get("kind") != "file":
                continue
            caps_raw = (ev.data.get("capabilities") or "").lower()
            path = ev.data.get("path", "")
            if not caps_raw or not path:
                continue

            for cap_name, sev in DANGEROUS_CAPS.items():
                if cap_name in caps_raw:
                    results.append(
                        RuleResult(
                            rule_id=self.id,
                            title=f"{cap_name} on {path}",
                            description=(
                                f"File '{path}' has capability '{cap_name}' "
                                f"({caps_raw}). This may allow privilege "
                                "escalation."
                            ),
                            category="privilege-escalation",
                            severity=sev,
                            confidence=Confidence.MEDIUM,
                            evidence_ids=[ev.id],
                            validation_steps=[
                                f"Verify: getcap {path}",
                                f"Check what '{path}' does and whether the "
                                "capability can be abused.",
                                "Reference: capabilities(7) man page.",
                                "Reproduce only in a controlled lab.",
                            ],
                            references=[
                                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
                                "MITRE ATT&CK T1548",
                            ],
                            tags=["capabilities", cap_name],
                        )
                    )
                    break  # report only the first dangerous cap per file
        return results
