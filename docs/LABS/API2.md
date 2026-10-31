# Lab Guide: API2:2023 Broken Authentication

## 1. Concepts
Broken Authentication occurs when APIs fail to properly verify identity, allow authentication tokens to be manipulated or forged, or rely on weak password recovery and session management mechanisms.

## 2. Endpoints Under Test
- `POST /api/v1/auth/session-exchange`
- `POST /api/v1/auth/forgot-password`
- `POST /api/v1/auth/reset-password`

## 3. Objective
1. Construct an unsigned JWT token with `"alg": "none"` claiming administrative subject `sub: "5"`.
2. Submit the token to `/api/v1/auth/session-exchange` to obtain an active administrator session and flag `FLAG{API2_BROKEN_AUTH_TOKEN_FORGED_3391}`.
3. Exploit predictable reset tokens on `/api/v1/auth/forgot-password` to reset Charlie's account.

## 4. Evidence Requirements
- Raw request and response showing session exchange granting an administrator token.
- Raw response demonstrating password reset using the predictable PIN.
- Captured flag: `FLAG{API2_BROKEN_AUTH_TOKEN_FORGED_3391}`.

## 5. Remediation Exercise
- Inspect [app/routers/auth.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/auth.py).
- Review how `# FIX: API2-Broken-Auth` forces `algorithms=["HS256"]` and verifies HMAC signatures cryptographically.
- Confirm `LAB_MODE=fixed` rejects unsigned tokens with `401 Unauthorized`.
