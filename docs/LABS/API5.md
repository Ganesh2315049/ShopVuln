# Lab Guide: API5:2023 Broken Function Level Authorization (BFLA)

## 1. Concepts
Broken Function Level Authorization occurs when an API fails to enforce role-based access control (RBAC), allowing standard users to invoke administrative or seller functions by simply navigating to those endpoints.

## 2. Endpoints Under Test
- `GET /api/v1/admin/export-users`
- `PUT /api/v1/products/{product_id}/price`

## 3. Objective
1. Authenticate as customer Alice and invoke `GET /api/v1/admin/export-users`.
2. Tamper with product #1's price via `PUT /api/v1/products/1/price` without owning the product.
3. Capture flag: `FLAG{API5_BFLA_ADMIN_EXPORT_EXTRACTED_4412}`.

## 4. Evidence Requirements
- Successful export of database users under customer credentials.
- Updated product price modified by customer role.
- Captured flag.

## 5. Remediation Exercise
- Inspect [app/routers/admin.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/admin.py).
- Review `require_admin` dependency enforcement.
- Verify `LAB_MODE=fixed` blocks customer access with `403 Forbidden`.
