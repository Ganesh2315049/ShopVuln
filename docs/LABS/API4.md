# Lab Guide: API4:2023 Unrestricted Resource Consumption

## 1. Concepts
APIs that do not restrict resource allocation (payload size, page limits, batch quantities, CPU/memory intensive operations) are vulnerable to Denial of Service (DoS) and infrastructure exhaustion.

## 2. Endpoints Under Test
- `GET /api/v1/products?limit=...`
- `POST /api/v1/cart/batch-add`

## 3. Objective
1. Query `GET /api/v1/products?limit=500` without limits.
2. Submit a batch cart addition with excessive item quantities (`999999`).
3. Capture flag: `FLAG{API4_RESOURCE_CONSUMPTION_DOS_AVOIDED_6623}`.

## 4. Evidence Requirements
- Response with `limit: 500` containing full product lists.
- Successful batch insertion with massive quantities.
- Captured flag.

## 5. Remediation Exercise
- Inspect [app/routers/products.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/products.py) and [app/routers/cart.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/cart.py).
- Review hard limit capping (`limit = min(max(1, limit), 20)`).
- Verify `LAB_MODE=fixed` caps pagination and rejects excessive cart batches with `400 Bad Request`.
