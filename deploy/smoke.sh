#!/usr/bin/env bash
# Smoke sonar.qa.guru: HTTPS system status. Tokens never printed.
set -euo pipefail

URL="${SONAR_URL:-https://sonar.qa.guru}"

status="$(curl -sfS --max-time 30 "${URL}/api/system/status")"
echo "${status}" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get("status")=="UP", d; print("status: UP", d.get("version",""))'

echo "OK: ${URL}"
