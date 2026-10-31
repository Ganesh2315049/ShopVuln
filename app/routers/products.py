"""Product catalog router implementing:
- API4: Unrestricted Resource Consumption (unbounded pagination)
- API5: Broken Function Level Authorization (seller/admin price updates)
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from app.config import settings
from app.core.runtime import runtime_config
from app.core.security import get_current_user
from app.database import get_db
from app.models import LabFlag, Product, User

router = APIRouter(prefix="/api/v1/products", tags=["API4 & API5 (Products)"])


class ProductResponse(BaseModel):
    id: int
    title: str
    description: str
    price: float
    stock: int
    category: str
    seller_id: int

    model_config = ConfigDict(from_attributes=True)


class ProductListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[ProductResponse]
    flag: Optional[str] = None


class PriceUpdateRequest(BaseModel):
    price: float


# ==============================================================================
# Scenario 4.1: Unrestricted Resource Consumption (Unbounded Pagination)
# ==============================================================================
@router.get("", response_model=ProductListResponse, summary="List catalog products (API4 Resource Consumption)")
def list_products(
    limit: int = Query(10, description="Number of products to retrieve"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
):
    """Retrieve catalog products with pagination.

    VULNERABLE MODE (API4-Unrestricted Resource Consumption):
    Allows arbitrarily high limit parameters (e.g. limit=1000000). The database
    is forced to process massive result sets, causing CPU/memory exhaustion.

    FIXED MODE:
    Strictly caps the pagination limit at 20 items per request.
    """
    query = db.query(Product).filter(Product.is_hidden == False)
    total_count = query.count()

    if runtime_config.is_vulnerable():
        # VULN: API4-Resource-Consumption - No upper bound on page size
        flag_val = None
        if limit > 100:
            flag = db.query(LabFlag).filter(LabFlag.category == "API4").first()
            if flag:
                flag_val = flag.flag_code

        items = query.offset(offset).limit(limit).all()
        return ProductListResponse(
            total=total_count,
            limit=limit,
            offset=offset,
            items=items,
            flag=flag_val,
        )
    else:
        # FIX: API4-Resource-Consumption - Enforce strict upper bound
        enforced_limit = min(max(1, limit), 20)
        items = query.offset(offset).limit(enforced_limit).all()
        return ProductListResponse(
            total=total_count,
            limit=enforced_limit,
            offset=offset,
            items=items,
            flag=None,
        )


# ==============================================================================
# Scenario 5.2: Broken Function Level Authorization (Seller Price Tampering)
# ==============================================================================
@router.put("/{product_id}/price", summary="Update product price (API5: BFLA Price Modification)")
def update_product_price(
    product_id: int,
    payload: PriceUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Modify product pricing.

    VULNERABLE MODE (API5-BFLA):
    Only checks if the caller is authenticated, omitting role and ownership verification.
    A regular customer can modify prices of products sold by any seller.

    FIXED MODE:
    Enforces that the caller is either an administrator or the specific seller who owns the product.
    """
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Product {product_id} not found",
        )

    if runtime_config.is_vulnerable():
        # VULN: API5-BFLA - Missing role & seller ownership check
        flag_val = None
        if current_user.role == "customer" or (current_user.role == "seller" and product.seller_id != current_user.id):
            flag = db.query(LabFlag).filter(LabFlag.category == "API5").first()
            if flag:
                flag_val = flag.flag_code

        product.price = payload.price
        db.commit()
        db.refresh(product)
        return {
            "status": "price_updated",
            "product_id": product.id,
            "new_price": product.price,
            "modified_by_role": current_user.role,
            "flag": flag_val,
        }
    else:
        # FIX: API5-BFLA - Verify seller role and item ownership or admin role
        if current_user.role not in ["seller", "admin"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Only merchants and administrators can modify pricing.",
            )
        if current_user.role == "seller" and product.seller_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not own this product listing.",
            )

        product.price = payload.price
        db.commit()
        db.refresh(product)
        return {
            "status": "price_updated",
            "product_id": product.id,
            "new_price": product.price,
            "modified_by_role": current_user.role,
            "flag": None,
        }
