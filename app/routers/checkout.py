"""Checkout and order processing router implementing:
- API6: Unrestricted Access to Sensitive Business Flows (coupon replay, negative checkout)
- API10: Unsafe Consumption of APIs (unvalidated third-party currency rates)
"""

from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.config import settings
from app.core.runtime import runtime_config
from app.core.security import get_current_user
from app.database import get_db
from app.models import Cart, CartItem, DiscountCode, LabFlag, Order, OrderItem, Product, User

router = APIRouter(prefix="/api/v1/checkout", tags=["API6: Business Flows & API10"])

# Track applied coupons per user in memory: {user_id: [coupon_code, ...]}
_applied_coupons_cache: Dict[int, List[str]] = {}


class ApplyCouponRequest(BaseModel):
    coupon_code: str
    cart_total: float


class CheckoutItemInput(BaseModel):
    product_id: int
    quantity: int


class ProcessOrderRequest(BaseModel):
    items: List[CheckoutItemInput]
    shipping_address: str
    discount_amount: float = 0.0


class CurrencyCalcRequest(BaseModel):
    amount_usd: float
    target_currency: str
    partner_rate_payload: Optional[dict] = None


# ==============================================================================
# Scenario 6.1: Coupon Code Replay & Stacking (API6 Business Flows)
# ==============================================================================
@router.post("/apply-coupon", summary="Apply discount code (API6: Business Flow Coupon Replay)")
def apply_coupon(
    payload: ApplyCouponRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Apply discount coupon to cart total.

    VULNERABLE MODE (API6-Business Flows):
    Fails to check if this single-use coupon was already redeemed by the user or
    enforce usage limits. Allows stacking the same coupon repeatedly until the
    order total becomes 0 or negative.

    FIXED MODE:
    Enforces atomic one-time coupon usage per customer account and verifies coupon
    max_uses.
    """
    coupon = db.query(DiscountCode).filter(DiscountCode.code == payload.coupon_code).first()
    if not coupon or not coupon.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired discount code",
        )

    if runtime_config.is_vulnerable():
        # VULN: API6-Business-Flow - No user-level replay prevention or stacking lock
        discount_value = (payload.cart_total * coupon.discount_percent) / 100.0
        new_total = max(0.0, payload.cart_total - discount_value)

        # Record coupon in user cache
        user_history = _applied_coupons_cache.setdefault(current_user.id, [])
        user_history.append(coupon.code)

        flag_val = None
        # If user replayed the coupon more than once or reduced price by 100%
        if user_history.count(coupon.code) > 1 or coupon.discount_percent >= 100.0:
            flag = db.query(LabFlag).filter(LabFlag.category == "API6").first()
            if flag:
                flag_val = flag.flag_code

        coupon.times_used += 1
        db.commit()

        return {
            "status": "coupon_applied",
            "coupon_code": coupon.code,
            "discount_percent": coupon.discount_percent,
            "discount_amount": discount_value,
            "new_total": new_total,
            "replays_detected": user_history.count(coupon.code),
            "flag": flag_val,
        }
    else:
        # FIX: API6-Business-Flow - Enforce single-use restriction and transaction limits
        user_history = _applied_coupons_cache.setdefault(current_user.id, [])
        if coupon.code in user_history:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Coupon code '{coupon.code}' has already been redeemed by your account.",
            )

        if coupon.times_used >= coupon.max_uses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Coupon code has reached maximum global redemption limit.",
            )

        user_history.append(coupon.code)
        coupon.times_used += 1
        db.commit()

        discount_value = (payload.cart_total * coupon.discount_percent) / 100.0
        new_total = max(0.0, payload.cart_total - discount_value)

        return {
            "status": "coupon_applied",
            "coupon_code": coupon.code,
            "discount_percent": coupon.discount_percent,
            "discount_amount": discount_value,
            "new_total": new_total,
            "flag": None,
        }


# ==============================================================================
# Scenario 6.2: Negative Quantity / Price Checkout (API6 Business Flows)
# ==============================================================================
@router.post("/process-order", summary="Process order checkout (API6: Business Flow Negative Items)")
def process_order(
    payload: ProcessOrderRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Execute checkout and place order.

    VULNERABLE MODE (API6-Business Flows):
    Accepts negative quantities in line items. A negative quantity subtracts from the
    total order value, effectively crediting the user balance upon checkout.

    FIXED MODE:
    Enforces that all item quantities are strictly positive integers (> 0) and verifies
    total order cost is positive and covered by balance.
    """
    if runtime_config.is_vulnerable():
        # VULN: API6-Business-Flow - Allows negative quantities
        computed_total = 0.0
        has_negative_qty = False

        for item in payload.items:
            product = db.query(Product).filter(Product.id == item.product_id).first()
            if not product:
                raise HTTPException(status_code=404, detail=f"Product {item.product_id} not found")
            if item.quantity < 0:
                has_negative_qty = True
            computed_total += product.price * item.quantity

        computed_total = computed_total - payload.discount_amount

        # Deduct or credit user balance
        current_user.balance -= computed_total

        # Create order
        new_order = Order(
            user_id=current_user.id,
            total_amount=computed_total,
            discount_amount=payload.discount_amount,
            status="paid",
            shipping_address=payload.shipping_address,
            tracking_number=f"TRACK-{current_user.username.upper()}-AUTO",
        )
        db.add(new_order)
        db.flush()

        for item in payload.items:
            product = db.query(Product).filter(Product.id == item.product_id).first()
            db.add(
                OrderItem(
                    order_id=new_order.id,
                    product_id=product.id,
                    quantity=item.quantity,
                    unit_price=product.price,
                )
            )

        db.commit()

        flag_val = None
        if has_negative_qty or computed_total < 0:
            flag = db.query(LabFlag).filter(LabFlag.category == "API6").first()
            if flag:
                flag_val = flag.flag_code

        return {
            "status": "order_processed",
            "order_id": new_order.id,
            "total_amount": computed_total,
            "user_balance": current_user.balance,
            "flag": flag_val,
        }
    else:
        # FIX: API6-Business-Flow - Validate strictly positive item quantities & positive total
        if not payload.items:
            raise HTTPException(status_code=400, detail="Cannot process order with empty items list.")

        computed_total = 0.0
        for item in payload.items:
            if item.quantity <= 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid quantity {item.quantity} for product {item.product_id}. Quantity must be >= 1.",
                )
            product = db.query(Product).filter(Product.id == item.product_id).first()
            if not product:
                raise HTTPException(status_code=404, detail=f"Product {item.product_id} not found")
            if product.stock < item.quantity:
                raise HTTPException(status_code=400, detail=f"Insufficient stock for {product.title}")
            computed_total += product.price * item.quantity

        final_total = max(0.0, computed_total - payload.discount_amount)
        if current_user.balance < final_total:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Insufficient store balance. Required: ${final_total:.2f}, Available: ${current_user.balance:.2f}",
            )

        current_user.balance -= final_total
        new_order = Order(
            user_id=current_user.id,
            total_amount=final_total,
            discount_amount=payload.discount_amount,
            status="paid",
            shipping_address=payload.shipping_address,
            tracking_number=f"TRACK-{current_user.username.upper()}-AUTO",
        )
        db.add(new_order)
        db.flush()

        for item in payload.items:
            product = db.query(Product).filter(Product.id == item.product_id).first()
            product.stock -= item.quantity
            db.add(
                OrderItem(
                    order_id=new_order.id,
                    product_id=product.id,
                    quantity=item.quantity,
                    unit_price=product.price,
                )
            )

        db.commit()

        return {
            "status": "order_processed",
            "order_id": new_order.id,
            "total_amount": final_total,
            "user_balance": current_user.balance,
            "flag": None,
        }


# ==============================================================================
# Scenario 10.2: Third-Party Currency Conversion Ingestion (API10 Unsafe Consumption)
# ==============================================================================
@router.post("/calculate-currency", summary="Convert prices via 3rd-party exchange rates (API10)")
def calculate_currency(payload: CurrencyCalcRequest, db: Session = Depends(get_db)):
    """Calculate converted price using external partner currency payload.

    VULNERABLE MODE (API10-Unsafe Consumption):
    Blindly consumes the incoming partner_rate_payload dict without validating
    numeric bounds or rate sanity (allowing negative or zero exchange rates).

    FIXED MODE:
    Validates exchange rate structure, bounds (must be > 0.01 and < 10000.0).
    """
    rate = 1.0
    if payload.partner_rate_payload:
        raw_rate = payload.partner_rate_payload.get("exchange_rate")
        if runtime_config.is_vulnerable():
            # VULN: API10 - Consuming unvalidated external rate
            if raw_rate is not None:
                rate = float(raw_rate)
            flag_val = None
            if rate <= 0.0 or rate > 100000.0:
                flag = db.query(LabFlag).filter(LabFlag.category == "API10").first()
                if flag:
                    flag_val = flag.flag_code
            return {
                "original_usd": payload.amount_usd,
                "currency": payload.target_currency,
                "applied_rate": rate,
                "converted_amount": payload.amount_usd * rate,
                "flag": flag_val,
            }
        else:
            # FIX: API10 - Validate external rates against realistic thresholds
            if raw_rate is None or not isinstance(raw_rate, (int, float)):
                raise HTTPException(status_code=400, detail="Invalid rate payload format from partner.")
            rate = float(raw_rate)
            if rate <= 0.05 or rate > 5000.0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Partner exchange rate {rate} outside acceptable sanity bounds [0.05, 5000.0].",
                )
            return {
                "original_usd": payload.amount_usd,
                "currency": payload.target_currency,
                "applied_rate": rate,
                "converted_amount": payload.amount_usd * rate,
                "flag": None,
            }

    # Default fallback
    return {
        "original_usd": payload.amount_usd,
        "currency": payload.target_currency,
        "applied_rate": rate,
        "converted_amount": payload.amount_usd * rate,
        "flag": None,
    }
