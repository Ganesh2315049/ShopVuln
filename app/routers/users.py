
"""API3: Broken Object Property Level Authorization (BOPLA) router.

Scenarios:
1. PUT /api/v1/users/profile - Mass assignment in vulnerable mode.
2. GET /api/v1/users/{user_id} - Excessive property exposure in vulnerable mode.
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy.orm import Session

from app.core.runtime import runtime_config
from app.core.security import get_current_user
from app.database import get_db
from app.models import LabFlag, User

router = APIRouter(
    prefix="/api/v1/users",
    tags=["API3: BOPLA (Users & Profiles)"],
)


class StrictUserProfileUpdate(BaseModel):
    """Only explicitly permitted profile fields are editable."""
    email: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class UserPublicResponse(BaseModel):
    """Sanitized public profile response."""
    id: int
    username: str
    role: str

    model_config = ConfigDict(from_attributes=True)


def get_api3_flag(db: Session) -> Optional[str]:
    """Return the configured API3 flag, if one exists."""
    flag = (
        db.query(LabFlag)
        .filter(LabFlag.category == "API3")
        .first()
    )
    return flag.flag_code if flag else None


# =============================================================================
# Scenario 3.1: Mass Assignment on Profile Update
# =============================================================================

@router.put(
    "/profile",
    summary="Update user profile (API3: BOPLA Mass Assignment)",
)
async def update_profile(
    body: Dict[str, Any] = Body(
        ...,
        description=(
            "Profile attributes. In vulnerable mode, the lab deliberately "
            "accepts sensitive fields for this security exercise."
        ),
        example={
            "role": "admin",
            "balance": 9999,
            "is_active": True,
        },
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update profile attributes.

    Vulnerable mode deliberately demonstrates unrestricted property binding.

    Fixed mode accepts only fields declared by StrictUserProfileUpdate.
    """
    if not isinstance(body, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The request body must be a JSON object.",
        )

    if runtime_config.is_vulnerable():
        # INTENTIONALLY VULNERABLE: training demonstration only.
        role_escalated = False

        for key, value in body.items():
            if (
                hasattr(current_user, key)
                and key not in {"id", "hashed_password"}
            ):
                setattr(current_user, key, value)

                if key == "role" and value == "admin":
                    role_escalated = True

        try:
            db.commit()
            db.refresh(current_user)
        except Exception:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="One or more profile values are invalid.",
            )

        flag_val = get_api3_flag(db) if role_escalated else None

        return {
            "status": "profile_updated",
            "user_id": current_user.id,
            "username": current_user.username,
            "role": current_user.role,
            "balance": current_user.balance,
            "flag": flag_val,
        }

    # FIXED MODE: reject properties outside the explicit allowlist.
    try:
        validated_data = StrictUserProfileUpdate.model_validate(body)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=exc.errors(include_context=False),
        ) from exc

    if validated_data.email is not None:
        current_user.email = validated_data.email

    try:
        db.commit()
        db.refresh(current_user)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The profile update contains invalid data.",
        )

    return {
        "status": "profile_updated",
        "user_id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "balance": current_user.balance,
        "flag": None,
    }


# =============================================================================
# Scenario 3.2: Excessive Object Property Exposure
# =============================================================================

@router.get(
    "/{user_id}",
    summary="Get user public info (API3: Excessive Property Exposure)",
)
def get_user_by_id(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve user details.

    Vulnerable mode deliberately exposes sensitive properties for the lab.

    Fixed mode returns only the sanitized public response schema.
    """
    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    if runtime_config.is_vulnerable():
        # INTENTIONALLY VULNERABLE: do not use this behavior in production.
        flag_val = None

        if user.id != current_user.id:
            flag_val = get_api3_flag(db)

        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "balance": user.balance,
            "hashed_password": user.hashed_password,
            "is_active": user.is_active,
            "created_at": (
                user.created_at.isoformat()
                if user.created_at
                else None
            ),
            "flag": flag_val,
        }

    # FIXED MODE: expose only approved public fields.
    return UserPublicResponse(
        id=user.id,
        username=user.username,
        role=user.role,
    )
