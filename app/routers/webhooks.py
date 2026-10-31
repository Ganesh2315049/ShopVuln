
"""
Webhook and third-party callback ingestion router.

API10: Unsafe Consumption of APIs
"""

import hashlib
import hmac
import json
import math

from typing import Optional, Any

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Request,
    Body,
    status,
)

from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy.orm import Session

from app.core.runtime import runtime_config
from app.database import get_db
from app.models import LabFlag, Order, User


router = APIRouter(
    prefix="/api/v1/webhooks",
    tags=["API10: Unsafe Consumption of APIs"],
)

PARTNER_WEBHOOK_SECRET = "shopvuln_partner_dispatch_hmac_secret_2026"


# ============================================================
# FIXED MODE: Strict shipping webhook schema
# ============================================================

class SafeShippingWebhookPayload(BaseModel):

    model_config = ConfigDict(extra="forbid")

    order_id: int

    status: str = Field(
        ...,
        pattern="^(in_transit|out_for_delivery|delivered|exception)$"
    )

    tracking_number: str


# ============================================================
# API10: Shipping Webhook
# ============================================================

@router.post(
    "/shipping-update",
    summary="Ingest partner shipping delivery callback (API10)",
    response_description="Shipping callback processing result",
)
async def ingest_shipping_update(
    request: Request,

    # Swagger JSON request body
    payload: Any = Body(
        ...,
        openapi_examples={
            "vulnerable_test": {
                "summary": "API10 vulnerable-mode test",
                "value": {
                    "order_id": 6,
                    "status": "in_transit",
                    "tracking_number": "TEST-API10",
                    "override_refund_amount": 10,
                },
            },
            "normal_callback": {
                "summary": "Normal shipping callback",
                "value": {
                    "order_id": 6,
                    "status": "in_transit",
                    "tracking_number": "TEST-API10",
                },
            },
        },
        json_schema_extra={"type": "object"},
    ),

    db: Session = Depends(get_db),

    x_partner_signature: Optional[str] = Header(
        default=None,
        alias="X-Partner-Signature"
    ),
):
    """
    VULNERABLE MODE:
    - Does not verify HMAC.
    - Accepts unsigned JSON.
    - Processes override_refund_amount.

    FIXED MODE:
    - Verifies HMAC-SHA256.
    - Validates SafeShippingWebhookPayload.
    - Rejects unknown fields.
    """

    # Read exact raw request bytes for HMAC verification.
    raw_body = await request.body()

    try:
        data = json.loads(raw_body)

    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(
            status_code=400,
            detail="Invalid JSON payload"
        )

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=400,
            detail="JSON payload must be an object"
        )

    # ========================================================
    # VULNERABLE MODE
    # ========================================================

    if runtime_config.is_vulnerable():

        # No signature verification or strict schema validation.
        order_id = data.get("order_id")

        order = db.query(Order).filter(
            Order.id == order_id
        ).first()

        if not order:
            raise HTTPException(
                status_code=404,
                detail=f"Order {order_id} not found"
            )

        # Update shipping status.
        if "status" in data:
            order.status = data["status"]

        flag_val = None
        refund_applied = False

        # Deliberately vulnerable: trusts injected refund field.
        if "override_refund_amount" in data:

            try:
                refund = float(data["override_refund_amount"])

            except (TypeError, ValueError):
                raise HTTPException(
                    status_code=400,
                    detail="Invalid refund amount"
                )

            if not math.isfinite(refund) or refund < 0:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid refund amount"
                )

            user = db.query(User).filter(
                User.id == order.user_id
            ).first()

            if user:
                user.balance += refund
                refund_applied = True

            # Retrieve API10 lab flag.
            flag = db.query(LabFlag).filter(
                LabFlag.category == "API10"
            ).first()

            if flag:
                flag_val = flag.flag_code

        db.commit()

        return {
            "status": "callback_processed",
            "order_id": order.id,
            "order_status": order.status,
            "injected_refund_applied": refund_applied,
            "flag": flag_val
        }

    # ========================================================
    # FIXED MODE
    # ========================================================

    else:

        # Step 1: Require partner signature.
        if not x_partner_signature:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    "Missing X-Partner-Signature header: "
                    "untrusted webhook rejected."
                )
            )

        # Step 2: Calculate expected HMAC-SHA256.
        expected_signature = hmac.new(
            PARTNER_WEBHOOK_SECRET.encode("utf-8"),
            raw_body,
            hashlib.sha256
        ).hexdigest()

        # Step 3: Verify signature.
        if not hmac.compare_digest(
            x_partner_signature,
            expected_signature
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    "Invalid HMAC signature: "
                    "payload authenticity verification failed."
                )
            )

        # Step 4: Validate against strict DTO.
        try:
            validated = SafeShippingWebhookPayload.model_validate(data)

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Schema validation failed: {str(e)}"
            )

        # Step 5: Find order.
        order = db.query(Order).filter(
            Order.id == validated.order_id
        ).first()

        if not order:
            raise HTTPException(
                status_code=404,
                detail=f"Order {validated.order_id} not found"
            )

        # Step 6: Update approved shipping fields only.
        order.status = validated.status
        order.tracking_number = validated.tracking_number

        db.commit()

        return {
            "status": "callback_processed",
            "order_id": order.id,
            "order_status": order.status,
            "flag": None
        }
