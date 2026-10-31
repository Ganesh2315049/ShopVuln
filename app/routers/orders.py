"""API1: Broken Object Level Authorization (BOLA) endpoints.

Scenarios:
1. GET /api/v1/orders/{order_id} - Accessing order details belonging to another customer.
2. GET /api/v1/returns/{return_id} - Viewing refund/return requests belonging to another customer.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.config import settings
from app.core.runtime import runtime_config
from app.core.security import get_current_user
from app.database import get_db
from app.models import LabFlag, Order, OrderItem, ReturnRequest, User
from pydantic import BaseModel, ConfigDict

router = APIRouter(prefix="/api/v1", tags=["API1: BOLA (Orders & Returns)"])


class OrderItemSchema(BaseModel):
    product_id: int
    quantity: int
    unit_price: float

    model_config = ConfigDict(from_attributes=True)


class OrderDetailResponse(BaseModel):
    id: int
    user_id: int
    total_amount: float
    discount_amount: float
    status: str
    shipping_address: str
    tracking_number: Optional[str]
    items: List[OrderItemSchema]
    flag: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ReturnRequestResponse(BaseModel):
    id: int
    order_id: int
    user_id: int
    reason: str
    status: str
    refund_amount: float
    flag: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# Scenario 1.1: Order Inspection by ID
# ==============================================================================
@router.get("/orders/{order_id}", response_model=OrderDetailResponse, summary="Retrieve order details by ID")
def get_order_by_id(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve order details.

    VULNERABLE MODE (API1-BOLA):
    Fails to verify if current_user owns the requested order or has admin privileges.
    Any authenticated user can view any other user's order details and tracking numbers.

    FIXED MODE:
    Enforces object-level ownership check: only the order owner or an admin can view it.
    """
    order = db.query(Order).filter(Order.id == order_id).first()
    if not order:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Order {order_id} not found",
        )

    if runtime_config.is_vulnerable():
        # VULN: API1-BOLA - No ownership verification
        flag_val = None
        # If user is accessing someone else's order, attach API1 flag as proof of exploit
        if order.user_id != current_user.id and current_user.role != "admin":
            flag = db.query(LabFlag).filter(LabFlag.category == "API1").first()
            if flag:
                flag_val = flag.flag_code

        return OrderDetailResponse(
            id=order.id,
            user_id=order.user_id,
            total_amount=order.total_amount,
            discount_amount=order.discount_amount,
            status=order.status,
            shipping_address=order.shipping_address,
            tracking_number=order.tracking_number,
            items=[
                OrderItemSchema(
                    product_id=it.product_id,
                    quantity=it.quantity,
                    unit_price=it.unit_price,
                )
                for it in order.items
            ],
            flag=flag_val,
        )
    else:
        # FIX: API1-BOLA - Strict ownership verification
        if order.user_id != current_user.id and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not have permission to view this order.",
            )

        return OrderDetailResponse(
            id=order.id,
            user_id=order.user_id,
            total_amount=order.total_amount,
            discount_amount=order.discount_amount,
            status=order.status,
            shipping_address=order.shipping_address,
            tracking_number=order.tracking_number,
            items=[
                OrderItemSchema(
                    product_id=it.product_id,
                    quantity=it.quantity,
                    unit_price=it.unit_price,
                )
                for it in order.items
            ],
            flag=None,
        )


# ==============================================================================
# Scenario 1.2: Return Request Inspection by ID
# ==============================================================================
@router.get("/returns/{return_id}", response_model=ReturnRequestResponse, summary="Retrieve return request details by ID")
def get_return_by_id(
    return_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve return request details.

    VULNERABLE MODE (API1-BOLA):
    Missing authorization check; users can enumerate returns and see refund amounts and reasons.

    FIXED MODE:
    Ensures current_user is either the return creator or an admin.
    """
    return_req = db.query(ReturnRequest).filter(ReturnRequest.id == return_id).first()
    if not return_req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Return request {return_id} not found",
        )

    if runtime_config.is_vulnerable():
        # VULN: API1-BOLA - Permissive object retrieval without subject validation
        flag_val = None
        if return_req.user_id != current_user.id and current_user.role != "admin":
            flag = db.query(LabFlag).filter(LabFlag.category == "API1").first()
            if flag:
                flag_val = flag.flag_code

        return ReturnRequestResponse(
            id=return_req.id,
            order_id=return_req.order_id,
            user_id=return_req.user_id,
            reason=return_req.reason,
            status=return_req.status,
            refund_amount=return_req.refund_amount,
            flag=flag_val,
        )
    else:
        # FIX: API1-BOLA - Authorize subject against object owner
        if return_req.user_id != current_user.id and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not have permission to view this return request.",
            )

        return ReturnRequestResponse(
            id=return_req.id,
            order_id=return_req.order_id,
            user_id=return_req.user_id,
            reason=return_req.reason,
            status=return_req.status,
            refund_amount=return_req.refund_amount,
            flag=None,
        )
