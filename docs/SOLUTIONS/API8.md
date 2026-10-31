# Solution: API8:2023 Security Misconfiguration

## 1. Walkthrough & Exploitation

### Step 1: Query Debug Diagnostics Endpoint
```bash
curl -s -X GET http://127.0.0.1:8000/api/v1/system/debug-info
```

### Exploit Evidence
```json
{
  "status": "debug_enabled",
  "python_version": "3.11.4",
  "jwt_algorithm": "HS256",
  "database_url": "sqlite:///./shopvuln.db",
  "flag": "FLAG{API8_SECURITY_MISCONFIG_DEBUG_LEAK_5510}"
}
```

### Step 2: Check Security Headers
```bash
curl -s -I http://127.0.0.1:8000/api/v1/system/headers-check
```
Notice omitted `X-Frame-Options` and `X-Content-Type-Options`.

---

## 2. Root Cause Analysis
Diagnostic/debug endpoints were left active in deployed environments without authentication, and standard defensive HTTP security headers were omitted from responses.

---

## 3. Patched Implementation
```python
# FIX: API8-Security-Misconfiguration
# 1. Disable debug endpoint in fixed mode:
raise HTTPException(status_code=404, detail="Diagnostics and debug endpoints are disabled.")

# 2. Hardened security headers:
response.headers["X-Content-Type-Options"] = "nosniff"
response.headers["X-Frame-Options"] = "DENY"
response.headers["Content-Security-Policy"] = "default-src 'self'"
```
