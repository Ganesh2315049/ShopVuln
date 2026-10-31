# Lab Guide: API3:2023 Broken Object Property Level Authorization (BOPLA)

## 1. Concepts
BOPLA encompasses both **Mass Assignment** (allowing clients to set internal, privileged, or immutable object properties) and **Excessive Data Exposure** (returning entire database models without filtering sensitive attributes).

## 2. Endpoints Under Test
- `PUT /api/v1/users/profile`
- `GET /api/v1/users/{user_id}`

## 3. Objective
1. Send an unexpected property payload (`{"role": "admin", "balance": 99999.0}`) to `PUT /api/v1/users/profile` to escalate privileges.
2. Query `GET /api/v1/users/1` to view Alice's bcrypt password hash and sensitive balance.
3. Capture flag: `FLAG{API3_BOPLA_ADMIN_FIELD_OVERWRITTEN_7721}`.

## 4. Evidence Requirements
- HTTP 200 response displaying upgraded role `"admin"` and balance.
- Response from `/api/v1/users/1` displaying `hashed_password`.
- Captured flag.

## 5. Remediation Exercise
- Inspect [app/routers/users.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/users.py).
- Review strict Pydantic DTO `StrictUserProfileUpdate` with `extra="forbid"`.
- Confirm `LAB_MODE=fixed` returns `422 Unprocessable Entity` for extra properties.
