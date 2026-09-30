#!/usr/bin/env bash
#
# NEXUS-R Lab runner
#
# Builds the vulnerable lab image, runs NEXUS-R inside it, and prints
# a summary of the findings and attack paths.
#
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] Building lab image..."
docker compose build

echo
echo "[*] Running NEXUS-R scan inside the lab container..."
docker compose run --rm nexus-lab-core bash -c '
  set -e
  mkdir -p /tmp/nexus-r-out
  nexus-r scan --output /tmp/nexus-r-out --verbose
  echo
  echo "========== LAB VERIFICATION =========="
  python3 - <<PY
import json
d = json.load(open("/tmp/nexus-r-out/report.json"))
rules = sorted({f["rule_id"] for f in d["findings"]})
paths = sorted({p["rule_id"] for p in d["attack_paths"]})
expected = {
    "NEXUS-SUID-001",
    "NEXUS-SUDO-001",
    "NEXUS-SUDO-002",
    "NEXUS-CAP-001",
    "NEXUS-CRON-001",
    "NEXUS-PATH-001",
    "NEXUS-SSH-001",
}
detected = set(rules) & expected
missing = expected - set(rules)
print(f"Findings : {d['"'"'summary'"'"']['"'"'finding_count'"'"']}")
print(f"Paths    : {d['"'"'summary'"'"']['"'"'attack_path_count'"'"']}")
print(f"Rules    : {', '.join(rules)}")
print(f"Paths    : {', '.join(paths)}")
print()
print(f"Expected rules: {len(expected)}")
print(f"Detected      : {len(detected)}")
if missing:
    print(f"MISSING       : {sorted(missing)}")
    raise SystemExit(1)
print("OK - all expected findings detected.")
PY
'
