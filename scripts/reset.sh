#!/usr/bin/env bash
# Reset ShopVuln database to default deterministic seed state
set -e

API_URL="${SHOPVULN_URL:-http://127.0.0.1:8000}"

echo "[*] Triggering ShopVuln lab reset via POST $API_URL/lab/reset..."
curl -s -X POST "$API_URL/lab/reset" \
  -H "Content-Type: application/json" | python -m json.tool

echo "[+] Lab reset complete. Default synthetic seed data restored."
