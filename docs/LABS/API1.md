# Lab Guide: API1:2023 Broken Object Level Authorization (BOLA)

## 1. Concepts
Broken Object Level Authorization (BOLA), also known as Insecure Direct Object References (IDOR), occurs when an API endpoint handles object identifiers (e.g., database IDs) from user requests without validating that the authenticated user possesses legitimate permissions to access or manipulate that specific object.

## 2. Endpoints Under Test
- `GET /api/v1/orders/{order_id}`
- `GET /api/v1/returns/{return_id}`

## 3. Objective
Authenticate as regular customer **Bob** (`bob` / `Password123!`), access order `#1` and return ticket `#1` belonging to **Alice**, and capture the secret tracking number and the API1 lab flag.

## 4. Evidence Requirements
- Successful HTTP 200 response when querying `/api/v1/orders/1` using Bob's Bearer token.
- Extracted JSON response containing Alice's shipping address and tracking number (`TRACK-ALICE-1001`).
- Captured flag: `FLAG{API1_BOLA_ORDER_DATA_EXPOSED_9182}`.

## 5. Remediation Exercise
- Inspect [app/routers/orders.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/orders.py).
- Review how `# FIX: API1-BOLA` validates that `order.user_id == current_user.id or current_user.role == "admin"`.
- Test fixed behavior by setting `LAB_MODE=fixed` and confirming the API responds with `403 Forbidden`.
