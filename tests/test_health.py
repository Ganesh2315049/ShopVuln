"""Tests for the health and root endpoints."""


def test_health_endpoint(client):
    """Verify GET /health returns 200 OK and expected status fields."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app"] == "ShopVuln"
    assert "version" in data
    assert "mode" in data
    assert "hints_enabled" in data
    assert "warning" in data


def test_root_endpoint(client):
    """Verify GET / returns welcome payload and documentation links."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "ShopVuln" in data["message"]
    assert data["docs_url"] == "/docs"
    assert data["health_url"] == "/health"
    assert "safety_notice" in data
