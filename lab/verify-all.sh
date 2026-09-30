#!/usr/bin/env bash
#
# NEXUS-R Lab - verify all scenarios
#
# Builds every lab image, runs NEXUS-R inside it, and compares the
# detected rule IDs against the expected ones declared in each
# scenario's expected.json.
#
set -euo pipefail
cd "$(dirname "$0")"

SCENARIOS=(
  "core:nexus-lab-core"
  "sudo-only:nexus-lab-sudo"
  "cron-only:nexus-lab-cron"
  "capabilities-only:nexus-lab-caps"
  "container-escape:nexus-lab-container"
)

FAILED=0

for entry in "${SCENARIOS[@]}"; do
  scenario="${entry%%:*}"
  service="${entry##*:}"

  echo "======================================================"
  echo "  Scenario: $scenario  (service: $service)"
  echo "======================================================"

  echo "[*] Building image..."
  docker compose build "$service" >/dev/null

  echo "[*] Running NEXUS-R inside the container..."
  docker compose run --rm "$service" bash -c '
    set -e
    mkdir -p /tmp/out
    nexus-r scan --output /tmp/out >/dev/null 2>&1
    cat /tmp/out/report.json
  ' > "/tmp/nexus-lab-${scenario}.json"

  echo "[*] Verifying expected rules..."
  if python3 "$(dirname "$0")/verify_one.py" "$scenario" "/tmp/nexus-lab-${scenario}.json" "scenarios/${scenario}/expected.json"; then
    echo "[OK] $scenario"
  else
    echo "[FAIL] $scenario"
    FAILED=$((FAILED + 1))
  fi
  echo
done

echo "======================================================"
if [ "$FAILED" -eq 0 ]; then
  echo "All scenarios passed."
  exit 0
else
  echo "$FAILED scenario(s) failed."
  exit 1
fi
