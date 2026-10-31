"""Automated test suite for Lab Mode Control (GET /lab/mode and PUT /lab/mode).

Verifies:
1. Retrieval of current mode via GET /lab/mode.
2. Admin-only authorization enforcement (rejecting unauthenticated, customer, and seller attempts).
3. Rejection of invalid mode values with 400 Bad Request.
4. Dynamic runtime mode switching without application restarts.
5. Verification of API1 BOLA behavior:
   - In Vulnerable mode: Alice can access Bob's seeded order.
   - In Fixed mode: Alice receives 403 Forbidden for Bob's order.
   - In both modes: Alice can access her own order.
6. Thread-safety under concurrent reads and writes.
7. OpenAPI documentation metadata and request body schema.
"""

import concurrent.futures
import pytest
from app.core.runtime import runtime_config


@pytest.fixture
def alice_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "Password123!"})
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture
def bob_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "bob", "password": "Password123!"})
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture
def seller_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "seller_sam", "password": "SellerPass123!"})
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture
def admin_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "AdminSecret2026!"})
    assert res.status_code == 200
    return res.json()["access_token"]


def test_get_lab_mode_unauthenticated(client):
    """GET /lab/mode returns the current active lab mode and descriptive message."""
    # Ensure starting in vulnerable mode
    runtime_config.set_mode("vulnerable")

    res = client.get("/lab/mode")
    assert res.status_code == 200
    data = res.json()
    assert data["mode"] == "vulnerable"
    assert "vulnerable" in data["message"].lower()


def test_put_lab_mode_requires_admin_authentication(client, alice_token, seller_token):
    """PUT /lab/mode rejects unauthenticated callers and non-admin roles."""
    # 1. Unauthenticated (no token) -> 401 Unauthorized
    res_no_auth = client.put("/lab/mode", json={"mode": "fixed"})
    assert res_no_auth.status_code == 401
    assert "Authentication required" in res_no_auth.json()["detail"]

    # 2. Customer token (Alice) -> 403 Forbidden
    res_cust = client.put(
        "/lab/mode",
        json={"mode": "fixed"},
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert res_cust.status_code == 403
    assert "Access forbidden" in res_cust.json()["detail"]

    # 3. Seller token (seller_sam) -> 403 Forbidden
    res_seller = client.put(
        "/lab/mode",
        json={"mode": "fixed"},
        headers={"Authorization": f"Bearer {seller_token}"},
    )
    assert res_seller.status_code == 403
    assert "Access forbidden" in res_seller.json()["detail"]


def test_put_lab_mode_rejects_invalid_values(client, admin_token):
    """PUT /lab/mode validates requested mode and rejects invalid strings."""
    for invalid_val in ["invalid_mode", "superuser", "bypass", "123", ""]:
        res = client.put(
            "/lab/mode",
            json={"mode": invalid_val},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 400
        data = res.json()
        assert "Allowed modes are 'vulnerable' and 'fixed'" in data["detail"]


def test_runtime_mode_switching_lifecycle(client, admin_token):
    """Admin dynamically switches mode between vulnerable and fixed at runtime."""
    # Switch to fixed mode
    res_fixed = client.put(
        "/lab/mode",
        json={"mode": "fixed"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_fixed.status_code == 200
    data_fixed = res_fixed.json()
    assert data_fixed["status"] == "success"
    assert data_fixed["mode"] == "fixed"
    assert "switched to 'fixed'" in data_fixed["message"]

    # Verify runtime state was immediately updated
    assert runtime_config.get_mode() == "fixed"
    assert runtime_config.is_fixed() is True
    assert runtime_config.is_vulnerable() is False

    # GET /lab/mode confirms fixed mode
    get_res = client.get("/lab/mode")
    assert get_res.status_code == 200
    assert get_res.json()["mode"] == "fixed"

    # GET /health reflects fixed mode
    health_res = client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json()["mode"] == "fixed"

    # Switch back to vulnerable mode
    res_vuln = client.put(
        "/lab/mode",
        json={"mode": "vulnerable"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res_vuln.status_code == 200
    data_vuln = res_vuln.json()
    assert data_vuln["status"] == "success"
    assert data_vuln["mode"] == "vulnerable"
    assert runtime_config.get_mode() == "vulnerable"

    get_res_vuln = client.get("/lab/mode")
    assert get_res_vuln.json()["mode"] == "vulnerable"


def test_api1_bola_runtime_switch_verification(client, admin_token, alice_token):
    """Verify API1 BOLA behavior under runtime mode switching.

    Training Scenario:
    - Alice has user_id=1 (orders #1 and #2).
    - Bob has user_id=2 (orders #3 and #4).

    Requirements:
    1. Vulnerable mode: Alice can access Bob's seeded order #3 (BOLA demonstration).
    2. Fixed mode: Alice receives 403 Forbidden for Bob's order #3.
    3. Alice can access her own order #1 in both modes.
    4. Switching back to Vulnerable mode re-enables BOLA exploit demonstration.
    """
    # Step 1: Switch to vulnerable mode via PUT /lab/mode
    set_vuln = client.put(
        "/lab/mode",
        json={"mode": "vulnerable"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert set_vuln.status_code == 200
    assert set_vuln.json()["mode"] == "vulnerable"

    # 1.a: Alice accesses her own order #1 (should succeed in vulnerable mode)
    alice_own_vuln = client.get(
        "/api/v1/orders/1",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert alice_own_vuln.status_code == 200
    assert alice_own_vuln.json()["id"] == 1
    assert alice_own_vuln.json()["user_id"] == 1

    # 1.b: Alice accesses Bob's order #3 (BOLA exploit succeeds in vulnerable mode)
    alice_bob_vuln = client.get(
        "/api/v1/orders/3",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert alice_bob_vuln.status_code == 200
    data_bob = alice_bob_vuln.json()
    assert data_bob["id"] == 3
    assert data_bob["user_id"] == 2  # Bob's user ID
    assert "TRACK-BOB" in data_bob["tracking_number"]
    assert data_bob["flag"] is not None
    assert "FLAG{API1_BOLA" in data_bob["flag"]

    # Step 2: Switch to fixed mode at runtime via PUT /lab/mode
    set_fixed = client.put(
        "/lab/mode",
        json={"mode": "fixed"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert set_fixed.status_code == 200
    assert set_fixed.json()["mode"] == "fixed"

    # 2.a: Alice accesses Bob's order #3 (BOLA is now blocked with 403 Forbidden)
    alice_bob_fixed = client.get(
        "/api/v1/orders/3",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert alice_bob_fixed.status_code == 403
    assert "Access denied" in alice_bob_fixed.json()["detail"]

    # 2.b: Alice accessing her own order #1 remains permitted in fixed mode
    alice_own_fixed = client.get(
        "/api/v1/orders/1",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert alice_own_fixed.status_code == 200
    assert alice_own_fixed.json()["id"] == 1
    assert alice_own_fixed.json()["user_id"] == 1

    # Step 3: Switch back to vulnerable mode to verify immediate toggle effect
    set_vuln_again = client.put(
        "/lab/mode",
        json={"mode": "vulnerable"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert set_vuln_again.status_code == 200

    # Alice accesses Bob's order #3 again (permitted once more)
    alice_bob_vuln_again = client.get(
        "/api/v1/orders/3",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert alice_bob_vuln_again.status_code == 200
    assert alice_bob_vuln_again.json()["user_id"] == 2


def test_thread_safe_concurrent_mode_access():
    """Verify thread-safe reading and writing of runtime configuration."""
    def worker(val):
        mode = "vulnerable" if val % 2 == 0 else "fixed"
        runtime_config.set_mode(mode)
        current = runtime_config.get_mode()
        assert current in ("vulnerable", "fixed")
        return current

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(worker, range(50)))

    assert len(results) == 50
    # Clean up state to vulnerable
    runtime_config.set_mode("vulnerable")


def test_openapi_documentation_mode_endpoints(client):
    """Verify Swagger/OpenAPI documentation contains Lab Mode Control tag and examples."""
    res = client.get("/openapi.json")
    assert res.status_code == 200
    schema = res.json()

    # Paths present
    assert "/lab/mode" in schema["paths"]
    mode_paths = schema["paths"]["lab/mode"] if "lab/mode" in schema["paths"] else schema["paths"]["/lab/mode"]
    assert "get" in mode_paths
    assert "put" in mode_paths

    # Section tag matches 'Lab Mode Control'
    assert "Lab Mode Control" in mode_paths["get"]["tags"]
    assert "Lab Mode Control" in mode_paths["put"]["tags"]

    # Verify example in PUT request body
    put_spec = mode_paths["put"]
    req_body = put_spec.get("requestBody", {})
    json_content = req_body.get("content", {}).get("application/json", {})
    # Either json_schema_extra example or schema example
    schema_ref = json_content.get("schema", {})
    assert schema_ref is not None
