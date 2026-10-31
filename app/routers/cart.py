"""Cart operations router implementing:
- API4: Unrestricted Resource Consumption (bulk cart item exhaustion)
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.config import settings
from app.core.runtime import runtime_config
from app.core.security import get_current_user
from app.database import get_db
from app.models import Cart, CartItem, LabFlag, Product, User

router = APIRouter(prefix="/api/v1/cart", tags=["API4: Resource Consumption (Cart)"])


class CartItemBatchInput(BaseModel):
    product_id: int
    quantity: int


class CartBatchAddRequest(BaseModel):
    items: List[CartItemBatchInput]


# ==============================================================================
# Scenario 4.2: Unrestricted Bulk Batch Add
# ==============================================================================
@router.post("/batch-add", summary="Batch add items to cart (API4: Unrestricted Resource Consumption)")
def batch_add_cart_items(
    payload: CartBatchAddRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Add multiple items to cart in a single batch request.

    VULNERABLE MODE (API4-Unrestricted Resource Consumption):
    Processes unbounded batch sizes and extreme item quantities without rate or
    resource limits, allowing memory exhaustion and database lockups.

    FIXED MODE:
    Caps batch size to a maximum of 10 items and item quantity to 20.
    """
    if runtime_config.is_vulnerable():
        # VULN: API4-Resource-Consumption - No upper bound on batch size or quantity
        flag_val = None
        if len(payload.items) > 30 or any(item.quantity > 100 for item in payload.items):
            flag = db.query(LabFlag).filter(LabFlag.category == "API4").first()
            if flag:
                flag_val = flag.flag_code

        # Get or create cart for user
        cart = db.query(Cart).filter(Cart.user_id == current_user.id).first()
        if not cart:
            cart = Cart(user_id=current_user.id)
            db.add(cart)
            db.commit()
            db.refresh(cart)

        for it in payload.items:
            db.add(CartItem(cart_id=cart.id, product_id=it.product_id, quantity=it.quantity))
        db.commit()

        return {
            "status": "batch_added",
            "items_count": len(payload.items),
            "flag": flag_val,
        }
    else:
        # FIX: API4-Resource-Consumption - Strict batch size and quantity enforcement
        MAX_BATCH_SIZE = 10
        MAX_QUANTITY_PER_ITEM = 20

        if len(payload.items) > MAX_BATCH_SIZE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Batch size limit exceeded. Maximum allowed is {MAX_BATCH_SIZE} items per request.",
            )

        for item in payload.items:
            if item.quantity <= 0 or item.quantity > MAX_QUANTITY_PER_ITEM:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid item quantity for product {item.product_id}. Must be between 1 and {MAX_QUANTITY_PER_ITEM}.",
                )

        cart = db.query(Cart).filter(Cart.user_id == current_user.id).first()
        if not cart:
            cart = Cart(user_id=current_user.id)
            db.add(cart)
            db.commit()
            db.refresh(cart)

        for it in payload.items:
            db.add(CartItem(cart_id=cart.id, product_id=it.product_id, quantity=it.quantity))
        db.commit()

        return {
            "status": "batch_added",
            "items_count": len(payload.items),
            "flag": None,
        }
