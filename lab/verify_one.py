"""Verify one NEXUS-R lab scenario against its expected rules.

Usage:
    python3 lab/verify_one.py <scenario_name> <report.json> <expected.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: verify_one.py <name> <report.json> <expected.json>")
        return 2

    name, report_path, expected_path = sys.argv[1], sys.argv[2], sys.argv[3]

    report = json.loads(Path(report_path).read_text())
    expected = json.loads(Path(expected_path).read_text())

    detected_rules = {f["rule_id"] for f in report.get("findings", [])}
    detected_paths = {p["rule_id"] for p in report.get("attack_paths", [])}

    expected_rules = set(expected.get("expected_rules", []))
    expected_paths = set(expected.get("expected_paths", []))

    missing_rules = expected_rules - detected_rules
    missing_paths = expected_paths - detected_paths

    print(f"  scenario     : {name}")
    print(f"  findings     : {len(report.get('findings', []))}")
    print(f"  attack_paths : {len(report.get('attack_paths', []))}")
    print(f"  rules needed : {len(expected_rules)}")
    print(f"  rules found  : {len(expected_rules & detected_rules)}")

    ok = True

    if missing_rules:
        ok = False
        print(f"  MISSING RULES: {sorted(missing_rules)}")

    if missing_paths:
        ok = False
        print(f"  MISSING PATHS: {sorted(missing_paths)}")

    if ok:
        print("  result       : PASS")
        return 0

    print("  result       : FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
