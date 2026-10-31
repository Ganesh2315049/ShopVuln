"""Tests for authentication, token issuance, and role handling."""

import jwt
from app.config import settings


def test_login_successful_customer(client):
    """Verify customer Alice can authenticate and receive JWT."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "Password123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "customer"
    assert data["username"] == "alice"
    assert data["user_id"] == 1


def test_login_successful_with_email(client):
    """Verify customer can also authenticate using synthetic email."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "alice@shopvuln.local", "password": "Password123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "alice"


def test_login_successful_seller_and_admin(client):
    """Verify seller and admin accounts authenticate correctly."""
    # Seller
    res_seller = client.post(
        "/api/v1/auth/login",
        json={"username": "seller_sam", "password": "SellerPass123!"},
    )
    assert res_seller.status_code == 200
    assert res_seller.json()["role"] == "seller"

    # Admin
    res_admin = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "AdminSecret2026!"},
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["role"] == "admin"


def test_login_invalid_password(client):
    """Verify login fails with invalid password."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "WrongPassword999!"},
    )
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]


def test_login_nonexistent_user(client):
    """Verify login fails for nonexistent username."""
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "ghost_user", "password": "SomePassword1!"},
    )
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]


def test_token_validation_get_me(client):
    """Verify GET /api/v1/auth/me returns profile when token is valid."""
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    profile = response.json()
    assert profile["username"] == "alice"
    assert profile["email"] == "alice@shopvuln.local"
    assert profile["role"] == "customer"
    assert profile["balance"] == 1500.0


def test_access_without_token(client):
    """Verify protected route rejects requests with missing Authorization header."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]


def test_access_with_tampered_token(client):
    """Verify protected route rejects invalid / tampered JWT signatures."""
    tampered_token = jwt.encode(
        {"sub": "1", "username": "alice", "role": "customer"},
        "wrong_fake_secret_key_xyz",
        algorithm="HS256",
    )
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert response.status_code == 401
    assert "Could not validate credentials" in response.json()["detail"]


def test_role_enforcement_admin_check(client):
    """Verify admin check endpoint allows admin and forbids customer."""
    # Alice (Customer) -> Forbidden (403)
    login_alice = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "Password123!"},
    )
    alice_token = login_alice.json()["access_token"]
    res_alice = client.get(
        "/api/v1/auth/admin-check",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert res_alice.status_code == 403

    # Admin -> Allowed (200)
    login_admin = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "AdminSecret2026!"},
    )
    admin_token = login_admin.json()["access_token"]
    res_admin = client.get(
        "/api/v1/auth/admin-check",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["role"] == "admin"


def test_role_enforcement_seller_check(client):
    """Verify seller check endpoint allows seller & admin, forbids customer."""
    login_seller = client.post(
        "/api/v1/auth/login",
        json={"username": "seller_sam", "password": "SellerPass123!"},
    )
    seller_token = login_seller.json()["access_token"]
    res_seller = client.get(
        "/api/v1/auth/seller-check",
        headers={"Authorization": f"Bearer {seller_token}"},
    )
    assert res_seller.status_code == 200
    assert res_seller.json()["role"] == "seller"

    # Alice (Customer) -> Forbidden (403)
    login_alice = client.post(
        "/api/v1/auth/login",
        json={"username": "alice", "password": "Password123!"},
    )
    alice_token = login_alice.json()["access_token"]
    res_alice = client.get(
        "/api/v1/auth/seller-check",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert res_alice.status_code == 403


def test_oauth2_form_token_endpoint(client):
    """Verify OAuth2 form URL encoded login works for Swagger UI."""
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "alice", "password": "Password123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
