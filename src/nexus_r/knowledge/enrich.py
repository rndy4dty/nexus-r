"""Report enrichment using the knowledge mappings.

Takes the JSON report dict and adds a `knowledge` block to each
finding and each attack path that has a mapping. Missing mappings are
not an error - the enrichment is best-effort.
"""

from __future__ import annotations

from typing import Any

from nexus_r.knowledge.mappings import get_knowledge


def enrich_item(item: dict[str, Any]) -> None:
    """Add a `knowledge` key to a finding or attack-path dict, in place."""
    rule_id = item.get("rule_id")
    if not rule_id:
        return
    entry = get_knowledge(rule_id)
    if entry is None:
        return
    item["knowledge"] = {
        "cwe": list(entry.cwe),
        "attack": list(entry.attack),
        "references": list(entry.references),
        "notes": list(entry.notes),
    }


def enrich_report(report: dict[str, Any]) -> dict[str, Any]:
    """Enrich findings and attack_paths in-place and return the report."""
    for finding in report.get("findings", []):
        enrich_item(finding)
    for path in report.get("attack_paths", []):
        enrich_item(path)
    return report
