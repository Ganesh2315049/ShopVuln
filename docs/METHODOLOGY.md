# Practical API Vulnerability Assessment and Penetration Testing (VAPT) Methodology

This methodology provides an end-to-end operational framework for assessing modern REST APIs, microservices, and GraphQL/gRPC interfaces based on the OWASP API Security Top 10 (2023).

---

## 1. Information Gathering & Reconnaissance

### 1.1 Discovery & Documentation Analysis
- **OpenAPI / Swagger Inspection**:
  - Review `/openapi.json`, `/docs`, `/redoc`, or `/swagger/v1/swagger.json`.
  - Extract all documented endpoints, parameter schemas, response DTOs, and authentication headers.
- **Shadow & Legacy Endpoint Discovery**:
  - Fuzz for undocumented API versions (`/api/v1_legacy/`, `/api/v2-preview/`, `/api/beta/`).
  - Use content discovery tools (`ffuf`, `gobuster`, `dirsearch`) with tailored API wordlists (`SecLists/Discovery/Web-Content/api/`).
- **Traffic Interception Setup**:
  - Configure Burp Suite / OWASP ZAP proxy on `127.0.0.1:8080`.
  - Ensure SSL interception certificates are installed if testing HTTPS endpoints.

---

## 2. Authentication & Session Testing

- **Token Inspection**:
  - Decode JWT tokens via jwt.io or Burp JWT Editor.
  - Test for algorithm switching (`alg: none`, HMAC vs RSA public key confusion).
  - Verify expiration (`exp`), subject (`sub`), and issuer (`iss`) claim enforcement.
- **Credential Handling**:
  - Test login rate-limiting and brute-force defenses on `/api/v1/auth/login`.
  - Test password reset workflows for deterministic/predictable reset tokens or lack of validation.

---

## 3. Authorization & Access Control Testing

### 3.1 Broken Object Level Authorization (BOLA / IDOR)
- **Multi-Account Matrix**:
  - Create two accounts with identical privilege tiers (User A: Alice, User B: Bob).
  - Intercept authenticated requests from User A and swap object IDs with User B's resources.
  - Verify if IDs are guessable sequential integers, UUIDs, or hashes.
- **Object Types to Test**:
  - Orders (`/api/v1/orders/{id}`), return tickets (`/api/v1/returns/{id}`), carts, invoices, and private messages.

### 3.2 Broken Function Level Authorization (BFLA)
- **Privilege Escalation**:
  - Identify administrative endpoints (e.g., `/api/v1/admin/*`, `/api/v1/system/*`).
  - Replay administrative requests using standard customer bearer tokens.
  - Test HTTP verb tampering (e.g., swapping `GET` to `PUT` or `DELETE`).

---

## 4. Property-Level Authorization & Data Exposure (BOPLA)

- **Mass Assignment**:
  - Inspect backend model definitions and client update endpoints (`PUT /api/v1/users/profile`).
  - Attempt to inject administrative properties (`role`, `is_admin`, `balance`, `permissions`, `is_verified`).
- **Excessive Data Exposure**:
  - Analyze server responses on public lookup endpoints (`GET /api/v1/users/{id}`).
  - Check for sensitive fields like password hashes, internal IDs, and payment tokens.

---

## 5. Business Logic & Rate Limiting

- **Business Flow Vulnerabilities**:
  - Test promo code and coupon reuse/stacking across transactions.
  - Test negative integers, floating-point rounding errors, and zero-dollar checkouts.
  - Test concurrent requests (race conditions) using Turbo Intruder.
- **Resource Consumption**:
  - Test extreme values in pagination parameters (`limit=1000000`).
  - Test payload size limits, batch requests (`/api/v1/cart/batch-add`), and file upload size caps.

---

## 6. Server-Side Request Forgery & Third-Party Integrations

- **SSRF Testing**:
  - Identify endpoints accepting URLs (webhooks, PDF generators, image parsers, shipping previews).
  - Test internal IP ranges (`127.0.0.1`, `localhost`, internal ports like `9000`).
  - *Safety Rule*: Never target external production infrastructure or real cloud metadata during unauthorized tests.
- **Unsafe API Consumption**:
  - Test webhook endpoints for missing cryptographic signatures (HMAC).
  - Inject unexpected fields into partner callbacks to check for balance tampering or unauthenticated state changes.

---

## 7. Reporting & Remediation Verification

- Document reproduction steps with raw curl commands and HTTP requests/responses.
- Identify the exact root cause in application source code.
- Provide targeted patches adhering to least privilege, strict DTO schema validation, and defensive coding.
