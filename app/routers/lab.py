"""Lab control router: reset, hints, scoreboard, and flag submission."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from app.config import settings
from app.core.runtime import runtime_config
from app.core.security import require_admin
from app.database import get_db
from app.models import LabFlag, User
from app.schemas.lab import (
    LabModeResponse,
    LabModeUpdateRequest,
    LabModeUpdateResponse,
)

router = APIRouter(prefix="/lab", tags=["Lab Management & CTF"])

# Lab hints repository mapped to OWASP API Security Top 10
HINTS_CATALOG = {
    "API1": {
        "title": "API1: Broken Object Level Authorization (BOLA)",
        "hint": (
            "Examine the ID parameters in order and return lookup endpoints (/api/v1/orders/{order_id} "
            "and /api/v1/returns/{return_id}). Does the backend verify that the authenticated subject owns the requested object? "
            "Try logging in as Bob and requesting Alice's order ID (Order 1)."
        ),
    },
    "API2": {
        "title": "API2: Broken Authentication",
        "hint": (
            "Review session exchange at /api/v1/auth/session-exchange and password resets at /api/v1/auth/forgot-password. "
            "Can you forge a JWT token with 'alg': 'none'? Is the password reset PIN predictable or based on user ID?"
        ),
    },
    "API3": {
        "title": "API3: Broken Object Property Level Authorization (BOPLA)",
        "hint": (
            "Inspect the profile update endpoint at PUT /api/v1/users/profile. What happens if you include extra fields like "
            "'role': 'admin' or 'balance': 99999? Also check GET /api/v1/users/{user_id} for excessive property exposure."
        ),
    },
    "API4": {
        "title": "API4: Unrestricted Resource Consumption",
        "hint": (
            "Analyze pagination query parameters on GET /api/v1/products?limit=... Does it permit huge limits? "
            "Also test bulk batch additions at POST /api/v1/cart/batch-add with extreme quantities."
        ),
    },
    "API5": {
        "title": "API5: Broken Function Level Authorization (BFLA)",
        "hint": (
            "Explore administrative endpoints such as GET /api/v1/admin/export-users and seller price modifications at "
            "PUT /api/v1/products/{product_id}/price. Can a normal customer invoke administrative export or tamper with seller prices?"
        ),
    },
    "API6": {
        "title": "API6: Unrestricted Access to Sensitive Business Flows",
        "hint": (
            "Investigate discount code redemption at POST /api/v1/checkout/apply-coupon. Can coupon DEVTEST100 be applied multiple "
            "times? Can you send negative item quantities at POST /api/v1/checkout/process-order to artificially credit your balance?"
        ),
    },
    "API7": {
        "title": "API7: Server-Side Request Forgery (SSRF)",
        "hint": (
            "Look at shipping label preview generation at POST /api/v1/shipping/fetch-label-preview. Can you point the partner_label_url "
            "to internal mock partner endpoints like http://127.0.0.1:9000/internal/admin/system-metrics? (Remember, external internet is sandboxed)."
        ),
    },
    "API8": {
        "title": "API8: Security Misconfiguration",
        "hint": (
            "Look for diagnostic endpoints such as GET /api/v1/system/debug-info. Does it leak environment variables and server internals? "
            "Check GET /api/v1/system/headers-check for missing security headers."
        ),
    },
    "API9": {
        "title": "API9: Improper Inventory Management",
        "hint": (
            "Look for undocumented, deprecated, or shadow endpoints hidden from OpenAPI docs (such as /api/v1_legacy/products/hidden "
            "or /api/inventory/internal-audit). What unreleased or confidential products exist in the catalog?"
        ),
    },
    "API10": {
        "title": "API10: Unsafe Consumption of APIs",
        "hint": (
            "Inspect partner courier webhooks at POST /api/v1/webhooks/shipping-update. Does it verify HMAC signatures or blindly trust "
            "injected properties such as 'override_refund_amount'?"
        ),
    },
}


class FlagSubmitRequest(BaseModel):
    flag_code: str


class FlagScoreItem(BaseModel):
    category: str
    description: str
    points: int
    is_solved: bool

    model_config = ConfigDict(from_attributes=True)


class ScoreboardResponse(BaseModel):
    total_score: int
    max_score: int
    solved_count: int
    total_challenges: int
    flags: List[FlagScoreItem]


# ==============================================================================
# Lab Mode Control Endpoints
# ==============================================================================
@router.get(
    "/mode",
    response_model=LabModeResponse,
    tags=["Lab Mode Control"],
    summary="Get current lab operational mode",
    description=(
        "Returns the currently active lab operational mode (`vulnerable` or `fixed`). "
        "In `vulnerable` mode, intentional OWASP API Security vulnerabilities are live and exploitable for training. "
        "In `fixed` mode, defensive validations, authorization checks, and secure coding mitigations are enforced."
    ),
    responses={
        200: {
            "description": "Current lab operational mode successfully retrieved",
            "content": {
                "application/json": {
                    "example": {
                        "mode": "vulnerable",
                        "message": "Current lab mode is 'vulnerable'. Vulnerabilities are actively exploitable.",
                    }
                }
            },
        }
    },
)
def get_lab_mode():
    """Retrieve the currently active lab mode at runtime."""
    active_mode = runtime_config.get_mode()
    desc = (
        "Vulnerabilities are actively exploitable for training."
        if active_mode == "vulnerable"
        else "Defenses and secure coding patterns are actively enforced."
    )
    return LabModeResponse(
        mode=active_mode,
        message=f"Current lab mode is '{active_mode}'. {desc}",
    )


@router.put(
    "/mode",
    response_model=LabModeUpdateResponse,
    tags=["Lab Mode Control"],
    summary="Switch lab operational mode (Admin only)",
    description=(
        "Switch the active lab operational mode between `vulnerable` and `fixed` at runtime. "
        "The change takes effect immediately on subsequent requests across all vulnerability handlers "
        "without requiring container restarts or modifying configuration files.\n\n"
        "**Security Requirement:** Only authenticated administrators can change the lab mode. "
        "Authorize with an admin token in Swagger UI (using the 'Authorize' button with Bearer token) before calling this endpoint."
    ),
    responses={
        200: {
            "description": "Lab mode successfully updated",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "mode": "fixed",
                        "message": "Lab mode successfully switched to 'fixed'.",
                    }
                }
            },
        },
        400: {"description": "Invalid mode specified. Allowed values are 'vulnerable' or 'fixed'."},
        401: {"description": "Authentication required: missing or invalid Bearer token"},
        403: {"description": "Forbidden: Requires administrator privileges"},
    },
)
def update_lab_mode(
    payload: LabModeUpdateRequest,
    current_user: User = Depends(require_admin),
):
    """Switch active lab operational mode dynamically at runtime."""
    requested_mode = payload.mode.strip().lower()
    if requested_mode not in ("vulnerable", "fixed"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid mode '{payload.mode}'. Allowed modes are 'vulnerable' and 'fixed'.",
        )

    # Apply mode change in centralized thread-safe runtime configuration
    updated_mode = runtime_config.set_mode(requested_mode)

    # Verify that the switch actually applied
    if runtime_config.get_mode() != requested_mode:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to apply runtime lab mode change.",
        )

    return LabModeUpdateResponse(
        status="success",
        mode=updated_mode,
        message=f"Lab mode successfully switched to '{updated_mode}'.",
    )


# ==============================================================================
# Lab Reset Endpoint
# ==============================================================================
@router.post("/reset", summary="Restore seed data and reset lab state")
def reset_lab(db: Session = Depends(get_db)):
    """Wipes mutable transactions and re-seeds deterministic synthetic records and flags."""
    from app.seed.seed_data import seed_database
    seed_database(db, force_reset=True)
    return {
        "status": "success",
        "message": "ShopVuln lab successfully restored to default seed state.",
        "mode": runtime_config.get_mode(),
        "hints_enabled": settings.LAB_HINTS == "on",
    }


# ==============================================================================
# Hints Endpoint
# ==============================================================================
@router.get("/hints/{category}", summary="Retrieve challenge hint for OWASP category")
def get_hint(category: str):
    """Returns educational guidance for a given category (API1 through API10) if LAB_HINTS=on."""
    cat_upper = category.upper()
    if cat_upper not in HINTS_CATALOG:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Category '{category}' not found. Available categories: API1 to API10.",
        )

    if settings.LAB_HINTS != "on":
        return {
            "status": "hints_disabled",
            "message": "Lab hints are currently disabled. Set LAB_HINTS=on in environment or .env to activate guidance.",
            "category": cat_upper,
        }

    info = HINTS_CATALOG[cat_upper]
    return {
        "status": "active",
        "category": cat_upper,
        "title": info["title"],
        "hint": info["hint"],
    }


# ==============================================================================
# Scoreboard Endpoint
# ==============================================================================
@router.get("/scoreboard", response_model=ScoreboardResponse, summary="View CTF scoreboard and flag progress")
def get_scoreboard(db: Session = Depends(get_db)):
    """Returns the current CTF score, solved flags, and total points."""
    flags = db.query(LabFlag).order_by(LabFlag.id).all()
    total_points = sum(f.points for f in flags if f.is_solved)
    max_points = sum(f.points for f in flags)
    solved_count = sum(1 for f in flags if f.is_solved)

    return ScoreboardResponse(
        total_score=total_points,
        max_score=max_points,
        solved_count=solved_count,
        total_challenges=len(flags),
        flags=flags,
    )


# ==============================================================================
# Flag Submission Endpoint
# ==============================================================================
@router.post("/flags/submit", summary="Submit a captured OWASP lab flag")
def submit_flag(payload: FlagSubmitRequest, db: Session = Depends(get_db)):
    """Submits and validates a captured flag code."""
    submitted = payload.flag_code.strip()
    flag = db.query(LabFlag).filter(LabFlag.flag_code == submitted).first()

    if not flag:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect flag code. Please verify your exploit evidence.",
        )

    if flag.is_solved:
        return {
            "status": "already_solved",
            "category": flag.category,
            "points": flag.points,
            "message": f"Flag for {flag.category} has already been recorded.",
        }

    flag.is_solved = True
    db.commit()

    return {
        "status": "correct",
        "category": flag.category,
        "points_awarded": flag.points,
        "message": f"Congratulations! You solved {flag.category}: {flag.description}.",
    }
