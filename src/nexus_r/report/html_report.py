"""Self-contained HTML report builder.

Converts the JSON report dict into a single, portable HTML file. No
external CSS/JS - everything is embedded, so the file can be opened
offline and shared as-is.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any

SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#0891b2",
    "info": "#6b7280",
}

SEVERITY_BG = {
    "critical": "#fee2e2",
    "high": "#fee2e2",
    "medium": "#fef3c7",
    "low": "#cffafe",
    "info": "#f3f4f6",
}

STATUS_COLORS = {
    "plausible": "#b91c1c",
    "hypothesis": "#d97706",
}


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _severity_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#6b7280")
    bg = SEVERITY_BG.get(sev, "#f3f4f6")
    return (
        f'<span class="badge" style="color:{color};background:{bg};'
        f'border:1px solid {color}33">{_esc(sev.upper())}</span>'
    )


def _confidence_badge(conf: str) -> str:
    return f'<span class="badge conf">{_esc(conf.upper())}</span>'


def _html_head(title: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                 Helvetica, Arial, sans-serif;
    margin: 0; padding: 0; background: #f9fafb; color: #111827;
    line-height: 1.5;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
  header {{
    background: #111827; color: #f9fafb; padding: 24px 0;
    border-bottom: 3px solid #b91c1c;
  }}
  header .container {{ padding: 0 24px; }}
  header h1 {{ margin: 0; font-size: 24px; letter-spacing: 0.5px; }}
  header .sub {{ color: #9ca3af; font-size: 14px; margin-top: 4px; }}
  .meta {{
    display: flex; flex-wrap: wrap; gap: 24px;
    margin-top: 16px; font-size: 13px; color: #d1d5db;
  }}
  .meta b {{ color: #f9fafb; }}
  h2 {{
    font-size: 18px; margin-top: 32px; padding-bottom: 8px;
    border-bottom: 2px solid #e5e7eb;
  }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0; }}
  .card {{
    background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;
    padding: 12px 16px; min-width: 110px;
  }}
  .card .label {{ font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; }}
  .card .value {{ font-size: 22px; font-weight: 600; margin-top: 2px; }}
  .item {{
    background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;
    padding: 16px; margin: 12px 0;
  }}
  .item.path {{ border-left: 5px solid #b91c1c; }}
  .item.finding {{ border-left: 5px solid #dc2626; }}
  .item h3 {{ margin: 0 0 6px; font-size: 15px; }}
  .row {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
  .badge {{
    display: inline-block; padding: 1px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.4px;
  }}
  .badge.conf {{ background: #e0e7ff; color: #3730a3; }}
  .rule-id {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
              font-size: 12px; color: #374151; background: #f3f4f6;
              padding: 1px 6px; border-radius: 3px; }}
  .desc {{ color: #374151; margin: 8px 0 4px; }}
  .kv {{ font-size: 13px; color: #4b5563; margin-top: 6px; }}
  .kv code {{ background: #f3f4f6; padding: 1px 4px; border-radius: 3px;
              font-size: 12px; }}
  details {{ margin-top: 8px; }}
  summary {{ cursor: pointer; font-size: 13px; color: #1f2937; font-weight: 500; }}
  ul {{ margin: 4px 0 4px 18px; padding: 0; font-size: 13px; color: #374151; }}
  li {{ margin: 2px 0; }}
  .ref a {{ color: #2563eb; text-decoration: none; font-size: 13px; }}
  .ref a:hover {{ text-decoration: underline; }}
  .empty {{ color: #6b7280; font-style: italic; padding: 8px 0; }}
  .trace {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: 12px; color: #4b5563; }}
  footer {{
    margin-top: 48px; padding: 24px 0; border-top: 1px solid #e5e7eb;
    font-size: 12px; color: #6b7280; text-align: center;
  }}
  .disclaimer {{
    background: #fef3c7; border: 1px solid #fcd34d; border-radius: 8px;
    padding: 12px 16px; font-size: 13px; color: #78350f; margin-top: 24px;
  }}
</style>
</head>
<body>
"""


def _html_header(report: dict[str, Any]) -> str:
    ver = report.get("nexus_r_version", "?")
    gen = report.get("generated_at", "?")
    scan = report.get("scan", {})
    collectors = scan.get("collectors_run", [])
    hostname = ""
    for ev in report.get("evidence", []):
        if ev.get("type") == "system" and "hostname" in ev.get("data", {}):
            hostname = ev["data"]["hostname"]
            break

    return f"""<header>
  <div class="container">
    <h1>NEXUS-R Security Report</h1>
    <div class="sub">Evidence-Driven Linux Security Research Engine</div>
    <div class="meta">
      <div><b>Host</b> {_esc(hostname or '?')}</div>
      <div><b>Generated</b> {_esc(gen)}</div>
      <div><b>NEXUS-R</b> {_esc(ver)}</div>
      <div><b>Collectors</b> {_esc(', '.join(collectors) or '?')}</div>
    </div>
  </div>
</header>
"""


def _html_summary(report: dict[str, Any]) -> str:
    s = report.get("summary", {})
    findings_by_sev = s.get("findings_by_severity", {})
    paths_by_sev = s.get("attack_paths_by_severity", {})

    cards = [
        ("Evidence", s.get("evidence_count", 0)),
        ("Findings", s.get("finding_count", 0)),
        ("Attack Paths", s.get("attack_path_count", 0)),
    ]
    sev_cards = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in findings_by_sev:
            sev_cards += (
                f'<div class="card"><div class="label">{_esc(sev)}</div>'
                f'<div class="value" style="color:{SEVERITY_COLORS[sev]}">'
                f'{findings_by_sev[sev]}</div></div>'
            )
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in paths_by_sev:
            sev_cards += (
                f'<div class="card"><div class="label">paths {_esc(sev)}</div>'
                f'<div class="value" style="color:{SEVERITY_COLORS[sev]}">'
                f'{paths_by_sev[sev]}</div></div>'
            )

    return f"""<div class="container">
<h2>Summary</h2>
<div class="cards">
  {''.join(f'<div class="card"><div class="label">{l}</div><div class="value">{v}</div></div>' for l, v in cards)}
</div>
<div class="cards">{sev_cards}</div>
"""


def _html_attack_paths(report: dict[str, Any]) -> str:
    paths = report.get("attack_paths", [])
    if not paths:
        return '<h2>Attack Paths</h2><p class="empty">No attack paths detected.</p>'

    items = []
    for p in paths:
        sev = p.get("severity", "info")
        conf = p.get("confidence", "low")
        status = p.get("status", "plausible")
        status_color = STATUS_COLORS.get(status, "#6b7280")
        steps_html = "".join(f"<li>{_esc(s)}</li>" for s in p.get("validation_steps", []))
        refs_html = "".join(
            f'<li class="ref"><a href="{_esc(r)}" target="_blank" rel="noopener">{_esc(r)}</a></li>'
            for r in p.get("references", [])
        )
        findings_str = ", ".join(p.get("finding_ids", [])) or "-"
        items.append(f"""
<div class="item path">
  <div class="row">
    {_severity_badge(sev)} {_confidence_badge(conf)}
    <span class="badge" style="background:{status_color}22;color:{status_color};border:1px solid {status_color}55">
      {_esc(status.upper())}
    </span>
    <span class="rule-id">{_esc(p.get('rule_id', ''))}</span>
  </div>
  <h3 style="margin-top:8px">{_esc(p.get('title', ''))}</h3>
  <div class="desc">{_esc(p.get('narrative', ''))}</div>
  <div class="kv">
    <b>entry</b> <code>{_esc(p.get('entry_point', '?'))}</code>
    &nbsp;&rarr;&nbsp;
    <b>target</b> <code>{_esc(p.get('target', '?'))}</code>
  </div>
  <div class="kv"><b>findings</b> <span class="trace">{_esc(findings_str)}</span></div>
  <details>
    <summary>Validation steps</summary>
    <ul>{steps_html}</ul>
  </details>
  <details>
    <summary>References</summary>
    <ul>{refs_html}</ul>
  </details>
</div>""")
    return "<h2>Attack Paths</h2>" + "".join(items)


def _html_findings(report: dict[str, Any]) -> str:
    findings = report.get("findings", [])
    if not findings:
        return '<h2>Findings</h2><p class="empty">No findings.</p>'

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(
        findings,
        key=lambda f: (order.get(f.get("severity", "info"), 9), f.get("rule_id", "")),
    )

    items = []
    for f in findings:
        sev = f.get("severity", "info")
        conf = f.get("confidence", "low")
        steps_html = "".join(
            f"<li>{_esc(s)}</li>" for s in f.get("validation_steps", [])
        )
        refs_html = "".join(
            f'<li class="ref"><a href="{_esc(r)}" target="_blank" rel="noopener">{_esc(r)}</a></li>'
            for r in f.get("references", [])
        )
        ev_str = ", ".join(f.get("evidence_ids", [])) or "-"
        items.append(f"""
<div class="item finding">
  <div class="row">
    {_severity_badge(sev)} {_confidence_badge(conf)}
    <span class="rule-id">{_esc(f.get('rule_id', ''))}</span>
  </div>
  <h3 style="margin-top:8px">{_esc(f.get('title', ''))}</h3>
  <div class="desc">{_esc(f.get('description', ''))}</div>
  <div class="kv"><b>evidence</b> <span class="trace">{_esc(ev_str)}</span></div>
  <details>
    <summary>Validation steps</summary>
    <ul>{steps_html}</ul>
  </details>
  <details>
    <summary>References</summary>
    <ul>{refs_html}</ul>
  </details>
</div>""")
    return "<h2>Findings</h2>" + "".join(items)


def _html_footer() -> str:
    return """</div>
<footer>
  <div class="container">
    <div class="disclaimer">
      <b>Authorized use only.</b> NEXUS-R is intended for authorized security
      assessment, lab environments, and systems you own or have explicit
      permission to test. Unauthorized use is illegal.
    </div>
    <div style="margin-top:16px">Generated by NEXUS-R</div>
  </div>
</footer>
</body>
</html>
"""


def build_html_report(report: dict[str, Any]) -> str:
    """Build the complete HTML report as a string."""
    title = "NEXUS-R Report"
    parts = [
        _html_head(title),
        _html_header(report),
        _html_summary(report),
        _html_attack_paths(report),
        _html_findings(report),
        _html_footer(),
    ]
    return "".join(parts)


def write_html_report(
    report: dict[str, Any],
    output_dir: Path,
    filename: str = "report.html",
) -> Path:
    """Write the HTML report and return the file path."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(build_html_report(report), encoding="utf-8")
    return path
