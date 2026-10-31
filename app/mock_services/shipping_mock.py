"""Mock shipping and internal partner service (Port 9000).

Provides internal-only mock endpoints for SSRF & 3rd-party integration training.
Safe, synthetic responses only; prevents access to external networks.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="ShopVuln Mock Shipping & Partner Service",
    description="Internal mock microservice for SSRF exercises and partner dispatch simulation.",
    version="1.0.0",
)


class ShippingLabelRequest(BaseModel):
    order_id: int
    recipient: str
    address: str


@app.get("/health")
def mock_health():
    return {
        "service": "internal-shipping-partner-service",
        "status": "online",
        "internal_only": True,
    }


@app.get("/internal/admin/system-metrics")
def internal_metrics():
    """Simulated internal management endpoint reachable via SSRF."""
    return {
        "status": "active",
        "node": "partner-gateway-node-01",
        "internal_ip": "10.0.0.99",
        "secret_token": "INTERNAL_PARTNER_API_KEY_SECRET_7721",
        "flag": "FLAG{API7_SSRF_INTERNAL_SERVICE_ACCESSED_9000}",
    }


@app.post("/api/v1/dispatch")
def dispatch_shipment(payload: ShippingLabelRequest):
    return {
        "status": "dispatched",
        "tracking_number": f"TRACK-LOCAL-{payload.order_id}-99281",
        "carrier": "MockPost Logistics",
        "partner_code": "PARTNER_LOCAL_DISPATCH",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=9000)
