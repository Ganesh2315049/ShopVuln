# Lab Guide: API8:2023 Security Misconfiguration

## 1. Concepts
Security misconfigurations occur when APIs expose verbose error messages, debug diagnostics, permissive CORS headers, or omit defense-in-depth HTTP security headers.

## 2. Endpoints Under Test
- `GET /api/v1/system/debug-info`
- `GET /api/v1/system/headers-check`

## 3. Objective
1. Discover and query the unauthenticated diagnostic endpoint `/api/v1/system/debug-info`.
2. Extract environment internals, secret configurations, and the flag: `FLAG{API8_SECURITY_MISCONFIG_DEBUG_LEAK_5510}`.
3. Verify missing security headers in response.

## 4. Evidence Requirements
- Raw response showing Python paths and JWT configuration settings.
- Captured flag.

## 5. Remediation Exercise
- Inspect [app/routers/system.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/system.py).
- Review how debug routes are disabled (`404 Not Found`) and how security headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`) are enforced in fixed mode.
