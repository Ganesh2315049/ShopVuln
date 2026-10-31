# PowerShell script to reset ShopVuln lab database
$ErrorActionPreference = "Stop"
$apiUrl = if ($env:SHOPVULN_URL) { $env:SHOPVULN_URL } else { "http://127.0.0.1:8000" }

Write-Host "[*] Triggering ShopVuln lab reset via POST $apiUrl/lab/reset..." -ForegroundColor Cyan
$response = Invoke-RestMethod -Uri "$apiUrl/lab/reset" -Method Post -ContentType "application/json"
$response | ConvertTo-Json -Depth 4
Write-Host "[+] Lab reset complete. Default synthetic seed data restored." -ForegroundColor Green
