# Lab Guide: API9:2023 Improper Inventory Management

## 1. Concepts
Improper Inventory Management occurs when organizations expose unpatched legacy endpoints, deprecated API versions, or undocumented shadow routes that bypass modern authentication, logging, and security controls.

## 2. Endpoints Under Test
- `GET /api/v1_legacy/products/hidden` (Undocumented)
- `GET /api/inventory/internal-audit` (Shadow endpoint)

## 3. Objective
1. Discover the undocumented legacy route `/api/v1_legacy/products/hidden` (which is excluded from OpenAPI docs).
2. Retrieve the confidential prototype listing (`Product #16: ShopVuln Internal Prototype Gizmo`) and mark flag `FLAG{API9_IMPROPER_INVENTORY_HIDDEN_PRODUCT_FOUND_2287}` as solved.

## 4. Evidence Requirements
- Successful HTTP 200 response displaying the unreleased prototype product details.
- Captured flag.

## 5. Remediation Exercise
- Inspect [app/routers/legacy.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/legacy.py).
- Review proper retirement of obsolete routes (`410 Gone`).
- Confirm `LAB_MODE=fixed` blocks access to legacy shadow endpoints.
