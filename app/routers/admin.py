"""Administrative router implementing:
- API5: Broken Function Level Authorization (administrative user database export)
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from app.config import settings
from app.core.runtime import runtime_config
from app.core.security import get_current_user, require_admin
from app.database import get_db
from app.models import LabFlag, User

router = APIRouter(prefix="/api/v1/admin", tags=["API5: BFLA (Admin Operations)"])


class AdminUserExportItem(BaseModel):
    id: int
    username: str
    email: str
    role: str
    balance: float
    is_active: bool

    model_config = ConfigDict(from_attributes=True)


class AdminUserExportResponse(BaseModel):
    total_users: int
    users: List[AdminUserExportItem]
    flag: Optional[str] = None


# ==============================================================================
# Scenario 5.1: Broken Function Level Authorization (Unprotected Admin Export)
# ==============================================================================
@router.get(
    "/export-users",
    response_model=AdminUserExportResponse,
    summary="Export all user database records (API5: BFLA Admin Function)",
)
def export_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export complete user accounts database.

    VULNERABLE MODE (API5-BFLA):
    Only checks that the request has an active login token, omitting role verification.
    Any standard customer can invoke this high-privilege administrative endpoint.

    FIXED MODE:
    Strictly enforces administrator role requirement via RBAC check.
    """
    if runtime_config.is_vulnerable():
        # VULN: API5-BFLA - Missing administrator role check
        flag_val = None
        if current_user.role != "admin":
            flag = db.query(LabFlag).filter(LabFlag.category == "API5").first()
            if flag:
                flag_val = flag.flag_code

        all_users = db.query(User).all()
        return AdminUserExportResponse(
            total_users=len(all_users),
            users=all_users,
            flag=flag_val,
        )
    else:
        # FIX: API5-BFLA - Enforce admin role validation
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Administrative privileges required to export user records.",
            )

        all_users = db.query(User).all()
        return AdminUserExportResponse(
            total_users=len(all_users),
            users=all_users,
            flag=None,
        )
