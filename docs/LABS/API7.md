# Lab Guide: API7:2023 Server-Side Request Forgery (SSRF)

## 1. Concepts
Server-Side Request Forgery occurs when an API fetches remote resources without validating user-supplied destination URIs, allowing attackers to coerce the server into connecting to internal microservices or cloud metadata.

## 2. Endpoints Under Test
- `POST /api/v1/shipping/fetch-label-preview`

## 3. Objective
1. Coerce the shipping preview relay to connect to the internal mock partner microservice on port 9000 at `http://127.0.0.1:9000/internal/admin/system-metrics`.
2. Extract the internal metrics and captured flag: `FLAG{API7_SSRF_INTERNAL_SERVICE_ACCESSED_9000}`.
3. *Note*: In accordance with lab safety rules, external network requests are strictly blocked by the internal sandbox filter.

## 4. Evidence Requirements
- JSON response showing `node: "partner-gateway-node-01"` and internal secret token.
- Captured flag.

## 5. Remediation Exercise
- Inspect [app/routers/shipping.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/shipping.py).
- Review the URL path allowlist (`ALLOWED_PATHS = ["/api/v1/dispatch", "/health"]`).
- Confirm `LAB_MODE=fixed` rejects internal admin paths with `403 Forbidden`.
