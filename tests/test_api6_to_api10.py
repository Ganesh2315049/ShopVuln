"""Regression tests for OWASP API Security API6 through API10.

Validates both vulnerable-mode exploits and fixed-mode defenses.
All SSRF and partner callbacks are tested locally against sandboxed mock services.
"""

import hashlib
import hmac
import json
import pytest
from app.config import settings
from app.routers.webhooks import PARTNER_WEBHOOK_SECRET


@pytest.fixture
def alice_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "Password123!"})
    return res.json()["access_token"]


@pytest.fixture
def bob_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "bob", "password": "Password123!"})
    return res.json()["access_token"]


# ==============================================================================
# API6: Unrestricted Access to Sensitive Business Flows
# ==============================================================================
def test_api6_coupon_reuse_vulnerable_mode(client, alice_token, monkeypatch):
    """VULN: Single-use DEVTEST100 coupon is applied and replayed for 100% off."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res1 = client.post(
        "/api/v1/checkout/apply-coupon",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"coupon_code": "DEVTEST100", "cart_total": 200.0},
    )
    assert res1.status_code == 200
    assert res1.json()["discount_amount"] == 200.0
    assert res1.json()["flag"] is not None
    assert "FLAG{API6_BUSINESS_FLOW" in res1.json()["flag"]


def test_api6_coupon_reuse_fixed_mode(client, bob_token, monkeypatch):
    """FIX: Replaying a single-use coupon is rejected with 400 Bad Request."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    # First application succeeds
    res1 = client.post(
        "/api/v1/checkout/apply-coupon",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"coupon_code": "WELCOME10", "cart_total": 100.0},
    )
    assert res1.status_code == 200

    # Second application of same coupon is rejected
    res2 = client.post(
        "/api/v1/checkout/apply-coupon",
        headers={"Authorization": f"Bearer {bob_token}"},
        json={"coupon_code": "WELCOME10", "cart_total": 100.0},
    )
    assert res2.status_code == 400
    assert "already been redeemed" in res2.json()["detail"]


def test_api6_negative_quantity_vulnerable_mode(client, alice_token, monkeypatch):
    """VULN: Negative item quantity subtracts from total, crediting user."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.post(
        "/api/v1/checkout/process-order",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "items": [{"product_id": 1, "quantity": -2}],
            "shipping_address": "123 Exploit Way",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total_amount"] < 0
    assert data["flag"] is not None
    assert "FLAG{API6_BUSINESS_FLOW" in data["flag"]


def test_api6_negative_quantity_fixed_mode(client, alice_token, monkeypatch):
    """FIX: Negative item quantity is strictly rejected with 400 Bad Request."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res = client.post(
        "/api/v1/checkout/process-order",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "items": [{"product_id": 1, "quantity": -2}],
            "shipping_address": "123 Exploit Way",
        },
    )
    assert res.status_code == 400
    assert "Quantity must be >= 1" in res.json()["detail"]


# ==============================================================================
# API7: Server-Side Request Forgery (SSRF)
# ==============================================================================
def test_api7_ssrf_internal_service_vulnerable_mode(client, alice_token, monkeypatch):
    """VULN: Fetches mock internal management metrics via SSRF and retrieves flag."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.post(
        "/api/v1/shipping/fetch-label-preview",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "order_id": 1,
            "partner_label_url": "http://127.0.0.1:9000/internal/admin/system-metrics",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["partner_response"]["node"] == "partner-gateway-node-01"
    assert data["flag"] is not None
    assert "FLAG{API7_SSRF" in data["flag"]


def test_api7_ssrf_safety_guard_blocks_external_access(client, alice_token, monkeypatch):
    """SAFETY: Attempts to target external internet or cloud metadata are blocked."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    # Cloud metadata attempt
    res_metadata = client.post(
        "/api/v1/shipping/fetch-label-preview",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"order_id": 1, "partner_label_url": "http://169.254.169.254/latest/meta-data/"},
    )
    assert res_metadata.status_code == 400
    assert "Lab Safety Guard" in res_metadata.json()["detail"]

    # Public internet attempt
    res_external = client.post(
        "/api/v1/shipping/fetch-label-preview",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"order_id": 1, "partner_label_url": "http://google.com/test"},
    )
    assert res_external.status_code == 400
    assert "Lab Safety Guard" in res_external.json()["detail"]


def test_api7_ssrf_fixed_mode(client, alice_token, monkeypatch):
    """FIX: Internal management paths are forbidden by URL allowlist."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    # Disallowed internal admin path
    res_disallowed = client.post(
        "/api/v1/shipping/fetch-label-preview",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "order_id": 1,
            "partner_label_url": "http://127.0.0.1:9000/internal/admin/system-metrics",
        },
    )
    assert res_disallowed.status_code == 403

    # Allowed safe path succeeds
    res_allowed = client.post(
        "/api/v1/shipping/fetch-label-preview",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={
            "order_id": 1,
            "partner_label_url": "http://127.0.0.1:9000/health",
        },
    )
    assert res_allowed.status_code == 200


# ==============================================================================
# API8: Security Misconfiguration
# ==============================================================================
def test_api8_debug_leak_vulnerable_mode(client, monkeypatch):
    """VULN: Debug info endpoint exposes internal environment variables & flag."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.get("/api/v1/system/debug-info")
    assert res.status_code == 200
    data = res.json()
    assert "jwt_algorithm" in data
    assert "sys_path" in data
    assert data["flag"] is not None
    assert "FLAG{API8_SECURITY_MISCONFIG" in data["flag"]


def test_api8_debug_leak_fixed_mode(client, monkeypatch):
    """FIX: Debug info endpoint is disabled and returns 404 Not Found."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res = client.get("/api/v1/system/debug-info")
    assert res.status_code == 404


def test_api8_security_headers_vulnerable_vs_fixed(client, monkeypatch):
    """VULN & FIX: Security headers comparison."""
    # Vulnerable mode: missing headers
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res_vuln = client.get("/api/v1/system/headers-check")
    assert "X-Frame-Options" not in res_vuln.headers

    # Fixed mode: hardened headers
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res_fixed = client.get("/api/v1/system/headers-check")
    assert res_fixed.headers["X-Frame-Options"] == "DENY"
    assert res_fixed.headers["X-Content-Type-Options"] == "nosniff"


# ==============================================================================
# API9: Improper Inventory Management
# ==============================================================================
def test_api9_undocumented_hidden_products_vulnerable_mode(client, monkeypatch):
    """VULN: Undocumented legacy endpoint exposes hidden prototype gizmo."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res = client.get("/api/v1_legacy/products/hidden")
    assert res.status_code == 200
    products = res.json()
    assert any("Prototype Gizmo" in p["title"] for p in products)


def test_api9_undocumented_legacy_fixed_mode(client, monkeypatch):
    """FIX: Legacy endpoints are decommissioned and return 410 Gone."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res = client.get("/api/v1_legacy/products/hidden")
    assert res.status_code == 410


def test_api9_shadow_inventory_audit_vulnerable_vs_fixed(client, monkeypatch):
    """VULN & FIX: Shadow inventory audit endpoint behavior."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res_vuln = client.get("/api/inventory/internal-audit")
    assert res_vuln.status_code == 200
    assert "FLAG{API9_IMPROPER_INVENTORY" in res_vuln.json()["flag"]

    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res_fixed = client.get("/api/inventory/internal-audit")
    assert res_fixed.status_code == 410


def test_api9_openapi_documentation(client):
    """DOC: API9 endpoints are visible in Swagger/OpenAPI with required tags, summaries, and descriptions."""
    res = client.get("/openapi.json")
    assert res.status_code == 200
    schema = res.json()
    paths = schema.get("paths", {})

    # Check both endpoints are present in OpenAPI schema
    assert "/api/v1_legacy/products/hidden" in paths
    assert "/api/inventory/internal-audit" in paths

    legacy_op = paths["/api/v1_legacy/products/hidden"]["get"]
    audit_op = paths["/api/inventory/internal-audit"]["get"]

    # Check Swagger tag: API9: Improper Inventory Management
    assert "API9: Improper Inventory Management" in legacy_op["tags"]
    assert "API9: Improper Inventory Management" in audit_op["tags"]

    # Check summaries
    assert legacy_op["summary"] == "Legacy hidden products endpoint."
    assert audit_op["summary"] == "Internal inventory audit endpoint."

    # Check descriptions
    assert legacy_op["description"] == "Demonstrates Improper Inventory Management through an undocumented legacy API."
    assert audit_op["description"] == "Demonstrates Improper Inventory Management through an undocumented shadow API."


# ==============================================================================
# API10: Unsafe Consumption of APIs
# ==============================================================================
def test_api10_untrusted_webhook_vulnerable_mode(client, monkeypatch):
    """VULN: Courier webhook accepts injected refund override and grants flag."""
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    payload = {
        "order_id": 1,
        "status": "delivered",
        "override_refund_amount": 500.0,
    }
    res = client.post("/api/v1/webhooks/shipping-update", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["injected_refund_applied"] is True
    assert data["flag"] is not None
    assert "FLAG{API10_UNSAFE_CONSUMPTION" in data["flag"]


def test_api10_untrusted_webhook_fixed_mode(client, monkeypatch):
    """FIX: Webhook rejects unsigned requests (401) and poisoned schemas (422)."""
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    payload = {
        "order_id": 1,
        "status": "delivered",
        "tracking_number": "TRACK-SAFE-1234",
    }
    raw_bytes = json.dumps(payload).encode("utf-8")

    # 1. Unsigned request -> 401 Unauthorized
    res_unsigned = client.post("/api/v1/webhooks/shipping-update", content=raw_bytes)
    assert res_unsigned.status_code == 401

    # 2. Signed valid request -> 200 OK
    valid_sig = hmac.new(PARTNER_WEBHOOK_SECRET.encode("utf-8"), raw_bytes, hashlib.sha256).hexdigest()
    res_signed = client.post(
        "/api/v1/webhooks/shipping-update",
        content=raw_bytes,
        headers={"X-Partner-Signature": valid_sig},
    )
    assert res_signed.status_code == 200

    # 3. Signed request with unauthorized extra property -> 422 Unprocessable Entity
    poisoned_payload = {
        "order_id": 1,
        "status": "invalid_unsupported_status",
        "tracking_number": "TRACK-1234",
    }
    poisoned_bytes = json.dumps(poisoned_payload).encode("utf-8")
    poisoned_sig = hmac.new(PARTNER_WEBHOOK_SECRET.encode("utf-8"), poisoned_bytes, hashlib.sha256).hexdigest()
    res_poisoned = client.post(
        "/api/v1/webhooks/shipping-update",
        content=poisoned_bytes,
        headers={"X-Partner-Signature": poisoned_sig},
    )
    assert res_poisoned.status_code == 422


def test_api10_currency_rate_injection_vulnerable_vs_fixed(client, monkeypatch):
    """VULN & FIX: Third-party currency rate boundary verification."""
    # Vulnerable mode accepts negative exchange rate
    monkeypatch.setattr(settings, "LAB_MODE", "vulnerable")
    res_vuln = client.post(
        "/api/v1/checkout/calculate-currency",
        json={
            "amount_usd": 100.0,
            "target_currency": "EUR",
            "partner_rate_payload": {"exchange_rate": -1.5},
        },
    )
    assert res_vuln.status_code == 200
    assert res_vuln.json()["converted_amount"] < 0
    assert "FLAG{API10_UNSAFE_CONSUMPTION" in res_vuln.json()["flag"]

    # Fixed mode rejects negative exchange rate
    monkeypatch.setattr(settings, "LAB_MODE", "fixed")
    res_fixed = client.post(
        "/api/v1/checkout/calculate-currency",
        json={
            "amount_usd": 100.0,
            "target_currency": "EUR",
            "partner_rate_payload": {"exchange_rate": -1.5},
        },
    )
    assert res_fixed.status_code == 400
