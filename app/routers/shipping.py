"""Shipping partner integration router implementing:
- API7: Server-Side Request Forgery (SSRF)

Safety Architecture:
All SSRF requests are strictly sandboxed. External internet, cloud metadata
(169.254.169.254), and local host ports other than the isolated mock shipping
service (port 9000) are blocked by the lab safety filter.
"""

from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, status
import httpx
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.config import settings
from app.core.runtime import runtime_config
from app.core.security import get_current_user
from app.database import get_db
from app.mock_services.shipping_mock import app as mock_shipping_app
from app.models import LabFlag, User

router = APIRouter(prefix="/api/v1/shipping", tags=["API7: SSRF (Shipping Integration)"])


class LabelPreviewRequest(BaseModel):
    order_id: int
    partner_label_url: str


class CourierTrackRequest(BaseModel):
    tracking_number: str
    courier_status_url: str


# Helper to safely dispatch to mock shipping service
async def _safe_mock_dispatch(target_url: str) -> dict:
    """Dispatches request to internal mock shipping service.

    Uses ASGITransport for in-process test execution and Docker isolation.
    """
    parsed = urlparse(target_url)

    # STRICT LAB SAFETY GUARD: Block any real external network access or metadata services
    allowed_hosts = ["127.0.0.1", "localhost", "mock-shipping"]
    if parsed.hostname not in allowed_hosts or parsed.port != 9000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Lab Safety Guard: External or unauthorized network access blocked. "
                "SSRF exercises must target local mock shipping service on port 9000 only."
            ),
        )

    # Use httpx with in-process mock_shipping_app ASGITransport or fallback to live port
    try:
        # First try via ASGITransport to support test runs without separate uvicorn process
        transport = httpx.ASGITransport(app=mock_shipping_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://mock-shipping:9000") as client:
            path = parsed.path
            if parsed.query:
                path = f"{path}?{parsed.query}"
            res = await client.get(path, timeout=3.0)
            return res.json()
    except Exception:
        # Fallback to direct HTTP socket
        async with httpx.AsyncClient(timeout=3.0) as client:
            res = await client.get(target_url)
            return res.json()


# ==============================================================================
# Scenario 7.1: Shipping Label Preview Relay (API7 SSRF)
# ==============================================================================
@router.post("/fetch-label-preview", summary="Fetch partner shipping label preview (API7 SSRF)")
async def fetch_label_preview(
    payload: LabelPreviewRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetches shipping label preview from partner URL.

    VULNERABLE MODE (API7-SSRF):
    Accepts arbitrary internal URLs on the partner service port.
    An attacker targeting 'http://127.0.0.1:9000/internal/admin/system-metrics'
    accesses restricted internal management telemetry and receives the API7 flag.

    FIXED MODE:
    Enforces a strict URL and path allowlist. Only designated dispatch routes
    are allowed; internal admin paths are rejected.
    """
    parsed = urlparse(payload.partner_label_url)

    if runtime_config.is_vulnerable():
        # VULN: API7-SSRF - Unrestricted path access on internal partner service
        result = await _safe_mock_dispatch(payload.partner_label_url)

        flag_val = None
        if "internal/admin" in parsed.path:
            flag = db.query(LabFlag).filter(LabFlag.category == "API7").first()
            if flag:
                flag_val = flag.flag_code

        return {
            "status": "label_fetched",
            "order_id": payload.order_id,
            "partner_response": result,
            "flag": flag_val,
        }
    else:
        # FIX: API7-SSRF - Strict allowlist of approved partner endpoints
        ALLOWED_PATHS = ["/api/v1/dispatch", "/health"]
        if parsed.path not in ALLOWED_PATHS:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Target path '{parsed.path}' is not in approved partner URL allowlist.",
            )

        result = await _safe_mock_dispatch(payload.partner_label_url)
        return {
            "status": "label_fetched",
            "order_id": payload.order_id,
            "partner_response": result,
            "flag": None,
        }


# ==============================================================================
# Scenario 7.2: Courier Tracking Relay (API7 SSRF)
# ==============================================================================
@router.post("/track-courier", summary="Relay courier tracking inquiry (API7 SSRF)")
async def track_courier(
    payload: CourierTrackRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Relays courier status inquiries to partner gateway.

    VULNERABLE MODE (API7-SSRF):
    Permits dynamic user-supplied URLs for partner dispatch.

    FIXED MODE:
    Disregards client-supplied host/scheme and uses internal configured base URL.
    """
    if runtime_config.is_vulnerable():
        # VULN: API7-SSRF
        result = await _safe_mock_dispatch(payload.courier_status_url)
        return {
            "status": "courier_status_retrieved",
            "tracking_number": payload.tracking_number,
            "courier_data": result,
        }
    else:
        # FIX: API7-SSRF - Pre-configured static destination only
        safe_url = f"{settings.MOCK_SHIPPING_URL}/health"
        result = await _safe_mock_dispatch(safe_url)
        return {
            "status": "courier_status_retrieved",
            "tracking_number": payload.tracking_number,
            "courier_data": result,
        }
