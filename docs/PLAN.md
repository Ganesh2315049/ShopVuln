# 30-Day API Security Learning Plan

A structured, hands-on syllabus designed to master the OWASP API Security Top 10 (2023) using the ShopVuln lab.

---

## Week 1: Foundations, Reconnaissance, and Object-Level Authorization

### Days 1–2: API Architectures & Tooling Setup
- **Topics**: REST principles, OpenAPI/Swagger specifications, HTTP methods, headers, and status codes.
- **Hands-on**:
  - Deploy ShopVuln locally via Docker or Python.
  - Configure Burp Suite, Postman, and curl to proxy through `127.0.0.1:8000`.
  - Explore `/docs`, `/openapi.json`, and run `scripts/smoke_test.sh`.

### Days 3–5: API1: Broken Object Level Authorization (BOLA)
- **Topics**: Understanding object ownership, sequential IDs vs UUIDs, and subject-to-object verification.
- **Hands-on with ShopVuln**:
  - Complete `docs/LABS/API1.md`.
  - Authenticate as Bob and capture Alice's order tracking details via `/api/v1/orders/1`.
  - Exploit return ticket authorization on `/api/v1/returns/1`.
  - Capture flag: `FLAG{API1_BOLA_ORDER_DATA_EXPOSED_9182}`.

### Days 6–7: Lab Review & Code Remediation
- Inspect [app/routers/orders.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/orders.py). Compare `# VULN: API1-BOLA` and `# FIX: API1-BOLA`.

---

## Week 2: Authentication, Property Authorization, and Function Controls

### Days 8–10: API2: Broken Authentication
- **Topics**: JWT token structures, cryptographic signing vs encoding, algorithm confusion (`alg: none`), and weak password reset flows.
- **Hands-on with ShopVuln**:
  - Complete `docs/LABS/API2.md`.
  - Forge an unsigned administrative token on `/api/v1/auth/session-exchange`.
  - Exploit predictable PIN generation on `/api/v1/auth/forgot-password`.
  - Capture flag: `FLAG{API2_BROKEN_AUTH_TOKEN_FORGED_3391}`.

### Days 11–12: API3: Broken Object Property Level Authorization (BOPLA)
- **Topics**: Mass assignment, parameter binding in ORMs, and excessive property exposure.
- **Hands-on with ShopVuln**:
  - Complete `docs/LABS/API3.md`.
  - Escalate Bob's privileges to admin via `PUT /api/v1/users/profile`.
  - Extract password hashes from `GET /api/v1/users/1`.
  - Capture flag: `FLAG{API3_BOPLA_ADMIN_FIELD_OVERWRITTEN_7721}`.

### Days 13–14: API5: Broken Function Level Authorization (BFLA)
- **Topics**: Role-Based Access Control (RBAC), administrative endpoint isolation, and verb tampering.
- **Hands-on with ShopVuln**:
  - Complete `docs/LABS/API5.md`.
  - Access administrative user dump via `GET /api/v1/admin/export-users` using customer credentials.
  - Capture flag: `FLAG{API5_BFLA_ADMIN_EXPORT_EXTRACTED_4412}`.

---

## Week 3: Resource Exhaustion, Business Logic, and Network Flaws

### Days 15–17: API4: Unrestricted Resource Consumption
- **Topics**: Pagination vulnerabilities, CPU/memory DoS, batch payload exhaustion.
- **Hands-on with ShopVuln**:
  - Complete `docs/LABS/API4.md`.
  - Send unbounded pagination requests on `GET /api/v1/products?limit=500`.
  - Send massive batch cart items on `POST /api/v1/cart/batch-add`.
  - Capture flag: `FLAG{API4_RESOURCE_CONSUMPTION_DOS_AVOIDED_6623}`.

### Days 18–20: API6: Unrestricted Access to Sensitive Business Flows
- **Topics**: Business workflow abuse, coupon code replay, negative quantity checkout, and race conditions.
- **Hands-on with ShopVuln**:
  - Complete `docs/LABS/API6.md`.
  - Replay single-use discount coupon `DEVTEST100`.
  - Place orders with negative quantities to increase user store balance.
  - Capture flag: `FLAG{API6_BUSINESS_FLOW_COUPON_REPLAYED_8819}`.

### Days 21–22: API7: Server-Side Request Forgery (SSRF)
- **Topics**: SSRF mechanics, attacking internal microservices, URL parsing flaws, and sandboxing.
- **Hands-on with ShopVuln**:
  - Complete `docs/LABS/API7.md`.
  - Target internal mock shipping service on port 9000 (`/internal/admin/system-metrics`).
  - Capture flag: `FLAG{API7_SSRF_INTERNAL_SERVICE_ACCESSED_9000}`.

---

## Week 4: Configurations, Inventory Management, 3rd-Party APIs, and CTF Completion

### Days 23–25: API8: Security Misconfiguration & API9: Improper Inventory
- **Topics**: Debug leaks, missing headers, undocumented/legacy APIs, shadow inventory.
- **Hands-on with ShopVuln**:
  - Complete `docs/LABS/API8.md` and `docs/LABS/API9.md`.
  - Discover and exploit `/api/v1/system/debug-info` and `/api/v1_legacy/products/hidden`.
  - Capture flags: `FLAG{API8_SECURITY_MISCONFIG_DEBUG_LEAK_5510}` and `FLAG{API9_IMPROPER_INVENTORY_HIDDEN_PRODUCT_FOUND_2287}`.

### Days 26–28: API10: Unsafe Consumption of APIs
- **Topics**: Webhook trust boundaries, HMAC signature validation, third-party data poisoning.
- **Hands-on with ShopVuln**:
  - Complete `docs/LABS/API10.md`.
  - Inject unauthorized refunds via `POST /api/v1/webhooks/shipping-update`.
  - Inject negative currency rates via `POST /api/v1/checkout/calculate-currency`.
  - Capture flag: `FLAG{API10_UNSAFE_CONSUMPTION_PAYLOAD_POISONED_1145}`.

### Days 29–30: Full CTF Scoreboard & Final Audit
- Submit all 10 flags to `POST /lab/flags/submit`.
- Verify total score is 1000/1000 on `GET /lab/scoreboard`.
- Run `scripts/verify_fixed.sh` to confirm understanding of defensive controls.
