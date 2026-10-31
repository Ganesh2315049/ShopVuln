#!/usr/bin/env bash
# Execute pytest with LAB_MODE=fixed to verify all defensive mitigations
set -e

echo "======================================================================"
echo "[*] Running ShopVuln Fixed-Mode Regression Verification"
echo "======================================================================"

export LAB_MODE=fixed

python -m pytest -v tests/test_api1_to_api5.py tests/test_api6_to_api10.py

echo "======================================================================"
echo "[+] All fixed-mode mitigations verified! Security controls active."
echo "======================================================================"
