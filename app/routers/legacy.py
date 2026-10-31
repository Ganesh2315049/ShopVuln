"""Undocumented legacy and shadow API routes implementing:
- API9: Improper Inventory Management (undocumented hidden catalog exposure & unmaintained shadow routes)
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from app.config import settings
from app.core.runtime import runtime_config
from app.database import get_db
from app.models import LabFlag, Product

router = APIRouter(tags=["API9: Improper Inventory Management"])


class LegacyProductResponse(BaseModel):
    id: int
    title: str
    price: float
    stock: int
    is_hidden: bool
    category: str

    model_config = ConfigDict(from_attributes=True)


# ==============================================================================
# Scenario 9.1: Undocumented Legacy Route (API9)
# ==============================================================================
@router.get(
    "/api/v1_legacy/products/hidden",
    response_model=List[LegacyProductResponse],
    include_in_schema=True,
    summary="Legacy hidden products endpoint.",
    description="Demonstrates Improper Inventory Management through an undocumented legacy API.",
)
def get_legacy_hidden_products(db: Session = Depends(get_db)):
    """Undocumented legacy endpoint for unreleased prototypes.

    VULNERABLE MODE (API9-Improper Inventory Management):
    Remains active and unauthenticated in production despite being superseded.
    Exposes restricted prototype items (Product #16 'ShopVuln Internal Prototype Gizmo').

    FIXED MODE:
    Properly decommissioned under API lifecycle policy (returns 410 Gone).
    """
    if runtime_config.is_vulnerable():
        # VULN: API9-Improper-Inventory - Legacy route active & unauthenticated
        hidden_products = db.query(Product).filter(Product.is_hidden == True).all()

        # Mark flag as solved in DB
        flag = db.query(LabFlag).filter(LabFlag.category == "API9").first()
        if flag:
            flag.is_solved = True
            db.commit()

        return hidden_products
    else:
        # FIX: API9-Improper-Inventory - Decommission deprecated legacy endpoint
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Endpoint deprecated and retired under API inventory and deprecation policy.",
        )


# ==============================================================================
# Scenario 9.2: Shadow Inventory Audit Endpoint (API9)
# ==============================================================================
@router.get(
    "/api/inventory/internal-audit",
    include_in_schema=True,
    summary="Internal inventory audit endpoint.",
    description="Demonstrates Improper Inventory Management through an undocumented shadow API.",
)
def get_shadow_inventory_audit(db: Session = Depends(get_db)):
    """Shadow unversioned inventory route left active by developers.

    VULNERABLE MODE (API9):
    Dumps total stock reserves, hidden flags, and category distributions.

    FIXED MODE:
    Returns 410 Gone.
    """
    if runtime_config.is_vulnerable():
        # VULN: API9 - Shadow route exposure
        flag = db.query(LabFlag).filter(LabFlag.category == "API9").first()
        flag_val = flag.flag_code if flag else None

        products = db.query(Product).all()
        return {
            "status": "legacy_shadow_inventory",
            "total_items": len(products),
            "hidden_count": sum(1 for p in products if p.is_hidden),
            "flag": flag_val,
        }
    else:
        # FIX: API9 - Enforce retirement
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Endpoint decommissioned.",
        )
