#!/usr/bin/env bash
# Smoke test script for ShopVuln API
set -e

API_URL="${SHOPVULN_URL:-http://127.0.0.1:8000}"

echo "[*] Checking ShopVuln Health Endpoint..."
curl -s -f "$API_URL/health" | python -m json.tool

echo "[*] Testing Customer Authentication (Alice)..."
LOGIN_RES=$(curl -s -X POST "$API_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "Password123!"}')
ALICE_TOKEN=$(echo "$LOGIN_RES" | python -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

if [ -n "$ALICE_TOKEN" ]; then
  echo "[+] Authentication successful! Token acquired."
else
  echo "[-] Authentication failed."
  exit 1
fi

echo "[*] Testing Profile Lookup (/api/v1/auth/me)..."
curl -s -H "Authorization: Bearer $ALICE_TOKEN" "$API_URL/api/v1/auth/me" | python -m json.tool

echo "[*] Testing Product Catalog (/api/v1/products?limit=2)..."
curl -s "$API_URL/api/v1/products?limit=2" | python -m json.tool

echo "[*] Testing Scoreboard (/lab/scoreboard)..."
curl -s "$API_URL/lab/scoreboard" | python -m json.tool

echo "[+] All smoke tests executed successfully!"
