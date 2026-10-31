# PowerShell smoke test script for ShopVuln API
$ErrorActionPreference = "Stop"
$apiUrl = if ($env:SHOPVULN_URL) { $env:SHOPVULN_URL } else { "http://127.0.0.1:8000" }

Write-Host "[*] Checking ShopVuln Health Endpoint..." -ForegroundColor Cyan
$health = Invoke-RestMethod -Uri "$apiUrl/health" -Method Get
$health | ConvertTo-Json -Depth 3

Write-Host "[*] Testing Customer Authentication (Alice)..." -ForegroundColor Cyan
$loginPayload = @{ username = "alice"; password = "Password123!" } | ConvertTo-Json
$loginRes = Invoke-RestMethod -Uri "$apiUrl/api/v1/auth/login" -Method Post -Body $loginPayload -ContentType "application/json"
$aliceToken = $loginRes.access_token

if ($aliceToken) {
    Write-Host "[+] Authentication successful! Token acquired." -ForegroundColor Green
} else {
    Write-Error "[-] Authentication failed."
}

Write-Host "[*] Testing Profile Lookup (/api/v1/auth/me)..." -ForegroundColor Cyan
$headers = @{ Authorization = "Bearer $aliceToken" }
$profile = Invoke-RestMethod -Uri "$apiUrl/api/v1/auth/me" -Method Get -Headers $headers
$profile | ConvertTo-Json -Depth 3

Write-Host "[*] Testing Product Catalog (/api/v1/products?limit=2)..." -ForegroundColor Cyan
$products = Invoke-RestMethod -Uri "$apiUrl/api/v1/products?limit=2" -Method Get
$products | ConvertTo-Json -Depth 3

Write-Host "[*] Testing Scoreboard (/lab/scoreboard)..." -ForegroundColor Cyan
$scoreboard = Invoke-RestMethod -Uri "$apiUrl/lab/scoreboard" -Method Get
$scoreboard | ConvertTo-Json -Depth 3

Write-Host "[+] All smoke tests executed successfully!" -ForegroundColor Green
