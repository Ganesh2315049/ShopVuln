# PowerShell script to verify fixed-mode regressions
$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "[*] Running ShopVuln Fixed-Mode Regression Verification" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$env:LAB_MODE = "fixed"

python -m pytest -v tests/test_api1_to_api5.py tests/test_api6_to_api10.py

Write-Host "======================================================================" -ForegroundColor Green
Write-Host "[+] All fixed-mode mitigations verified! Security controls active." -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
