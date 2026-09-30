"""Markdown report builder.

Produces a plain-text Markdown report suitable for inclusion in a
pentest report. No HTML, no CSS. Just headings, tables, and lists.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _md_escape(text: str) -> str:
    """Escape the few characters that break Markdown formatting."""
    if not isinstance(text, str):
        text = str(text)
    return text.replace("|", "\\|").replace("`", "\\`")


def _hostname_from_evidence(report: dict[str, Any]) -> str:
    for ev in report.get("evidence", []):
        if ev.get("type") == "system":
            data = ev.get("data", {})
            if "hostname" in data:
                return str(data["hostname"])
    return "?"


def _render_summary(report: dict[str, Any]) -> str:
    s = report.get("summary", {})
    lines: list[str] = ["## Summary", ""]
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Evidence items | {s.get('evidence_count', 0)} |")
    lines.append(f"| Findings | {s.get('finding_count', 0)} |")
    lines.append(f"| Attack paths | {s.get('attack_path_count', 0)} |")
    lines.append(f"| Hypotheses | {s.get('hypothesis_count', 0)} |")
    lines.append("")

    sev = s.get("findings_by_severity", {})
    if sev:
        lines.append("### Findings by severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for sname in SEVERITY_ORDER:
            if sname in sev:
                lines.append(f"| {sname} | {sev[sname]} |")
        lines.append("")

    conf = s.get("findings_by_confidence", {})
    if conf:
        lines.append("### Findings by confidence")
        lines.append("")
        lines.append("| Confidence | Count |")
        lines.append("|---|---|")
        for cname in ("high", "medium", "low"):
            if cname in conf:
                lines.append(f"| {cname} | {conf[cname]} |")
        lines.append("")

    return "\n".join(lines)


def _render_attack_paths(report: dict[str, Any]) -> str:
    paths = report.get("attack_paths", [])
    if not paths:
        return "## Attack Paths\n\n_No attack paths detected._\n"

    lines: list[str] = ["## Attack Paths", ""]
    for p in paths:
        sev = p.get("severity", "info").upper()
        conf = p.get("confidence", "low").upper()
        rid = p.get("rule_id", "?")
        title = p.get("title", "")
        lines.append(f"### [{sev}/{conf}] {rid} - {_md_escape(title)}")
        lines.append("")

        narrative = p.get("narrative", "")
        if narrative:
            lines.append(f"**Narrative:** {_md_escape(narrative)}")
            lines.append("")

        entry = p.get("entry_point", "?")
        target = p.get("target", "?")
        status = p.get("status", "?")
        lines.append(f"- **Entry:** `{entry}`")
        lines.append(f"- **Target:** `{target}`")
        lines.append(f"- **Status:** `{status}`")
        findings = p.get("finding_ids", [])
        if findings:
            lines.append(f"- **Findings:** {', '.join(f'`{f}`' for f in findings)}")
        lines.append("")

        steps = p.get("validation_steps", [])
        if steps:
            lines.append("**Validation steps:**")
            lines.append("")
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {_md_escape(step)}")
            lines.append("")

        refs = p.get("references", [])
        if refs:
            lines.append("**References:**")
            lines.append("")
            for r in refs:
                lines.append(f"- <{r}>")
            lines.append("")

        knowledge = p.get("knowledge", {})
        if knowledge:
            cwe = knowledge.get("cwe", [])
            attack = knowledge.get("attack", [])
            if cwe or attack:
                lines.append("**Knowledge:**")
                lines.append("")
                if cwe:
                    lines.append(f"- CWE: {', '.join(f'`{c}`' for c in cwe)}")
                if attack:
                    lines.append(f"- ATT&CK: {', '.join(f'`{a}`' for a in attack)}")
                lines.append("")

    return "\n".join(lines)


def _render_findings(report: dict[str, Any]) -> str:
    findings = report.get("findings", [])
    if not findings:
        return "## Findings\n\n_No findings._\n"

    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings = sorted(
        findings,
        key=lambda f: (order.get(f.get("severity", "info"), 9), f.get("rule_id", "")),
    )

    lines: list[str] = ["## Findings", ""]
    for f in findings:
        sev = f.get("severity", "info").upper()
        conf = f.get("confidence", "low").upper()
        rid = f.get("rule_id", "?")
        title = f.get("title", "")
        fid = f.get("id", "?")
        lines.append(f"### [{sev}/{conf}] {rid} - {_md_escape(title)}")
        lines.append("")
        lines.append(f"- **ID:** `{fid}`")

        desc = f.get("description", "")
        if desc:
            lines.append(f"- **Description:** {_md_escape(desc)}")

        ev = f.get("evidence_ids", [])
        if ev:
            lines.append(f"- **Evidence:** {', '.join(f'`{e}`' for e in ev)}")

        cat = f.get("category", "")
        if cat:
            lines.append(f"- **Category:** `{cat}`")

        lines.append("")

        steps = f.get("validation_steps", [])
        if steps:
            lines.append("**Validation steps:**")
            lines.append("")
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {_md_escape(step)}")
            lines.append("")

        refs = f.get("references", [])
        if refs:
            lines.append("**References:**")
            lines.append("")
            for r in refs:
                lines.append(f"- <{r}>")
            lines.append("")

        knowledge = f.get("knowledge", {})
        if knowledge:
            cwe = knowledge.get("cwe", [])
            attack = knowledge.get("attack", [])
            if cwe or attack:
                lines.append("**Knowledge:**")
                lines.append("")
                if cwe:
                    lines.append(f"- CWE: {', '.join(f'`{c}`' for c in cwe)}")
                if attack:
                    lines.append(f"- ATT&CK: {', '.join(f'`{a}`' for a in attack)}")
                lines.append("")

    return "\n".join(lines)


def _render_hypotheses(report: dict[str, Any]) -> str:
    hypotheses = report.get("hypotheses", [])
    if not hypotheses:
        return ""

    lines: list[str] = ["## Hypotheses", ""]
    lines.append(
        "_Hypotheses are advisory. They never substitute for findings "
        "and always require human validation (ADR-004)._"
    )
    lines.append("")

    for h in hypotheses:
        sev = h.get("severity", "info").upper()
        conf = h.get("confidence", "low").upper()
        hid = h.get("id", "?")
        title = h.get("title", "")
        mode = h.get("mode", "template")
        model = h.get("model", "")
        status = h.get("status", "needs_review")

        lines.append(f"### [{sev}/{conf}] {hid} - {_md_escape(title)}")
        lines.append("")
        lines.append(f"- **Mode:** `{mode}` ({model})")
        lines.append(f"- **Status:** `{status}`")

        fids = h.get("finding_ids", [])
        if fids:
            lines.append(f"- **Findings:** {', '.join(f'`{f}`' for f in fids)}")
        lines.append("")

        narrative = h.get("narrative", "")
        if narrative:
            lines.append(f"**Note:** {_md_escape(narrative)}")
            lines.append("")

        steps = h.get("validation_steps", [])
        if steps:
            lines.append("**Validation steps:**")
            lines.append("")
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {_md_escape(step)}")
            lines.append("")

    return "\n".join(lines)


def build_markdown_report(report: dict[str, Any]) -> str:
    """Build a complete Markdown report as a string."""
    version = report.get("nexus_r_version", "?")
    generated = report.get("generated_at", "?")
    hostname = _hostname_from_evidence(report)
    collectors = report.get("scan", {}).get("collectors_run", [])

    header: list[str] = []
    header.append(f"# NEXUS-R Security Report - {hostname}")
    header.append("")
    header.append(f"- **Generated:** {generated}")
    header.append(f"- **Host:** `{hostname}`")
    header.append(f"- **NEXUS-R:** {version}")
    header.append(f"- **Collectors:** {', '.join(collectors) or '-'}")
    header.append("")
    header.append("---")
    header.append("")

    footer: list[str] = []
    footer.append("---")
    footer.append("")
    footer.append(
        "**Authorized use only.** NEXUS-R is intended for authorized "
        "security assessment, lab environments, and systems you own or "
        "have explicit permission to test."
    )
    footer.append("")

    parts = [
        "\n".join(header),
        _render_summary(report),
        _render_attack_paths(report),
        _render_findings(report),
        _render_hypotheses(report),
        "\n".join(footer),
    ]
    return "\n".join(p for p in parts if p)


def write_markdown_report(
    report: dict[str, Any],
    output_dir: Path,
    filename: str = "report.md",
) -> Path:
    """Write the Markdown report and return the file path."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(build_markdown_report(report), encoding="utf-8")
    return path
