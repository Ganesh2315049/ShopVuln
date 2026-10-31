"""System and diagnostic router implementing:
- API8: Security Misconfiguration (verbose debug leak, missing security headers)
"""

import os
import sys
from fastapi import APIRouter, HTTPException, Response, status
from sqlalchemy.orm import Session
from fastapi import Depends
from app.config import settings
from app.core.runtime import runtime_config
from app.database import get_db
from app.models import LabFlag

router = APIRouter(prefix="/api/v1/system", tags=["API8: Security Misconfiguration"])


# ==============================================================================
# Scenario 8.1: Verbose Debug Endpoint & Environment Leak (API8)
# ==============================================================================
@router.get("/debug-info", summary="System runtime diagnostics (API8: Debug Leak)")
def get_debug_info(db: Session = Depends(get_db)):
    """System runtime diagnostics.

    VULNERABLE MODE (API8-Security Misconfiguration):
    Exposes sensitive environment variables, internal system paths, Python version,
    and server configuration without authentication.

    FIXED MODE:
    Completely disables debug diagnostics in non-development mode (returns 404 Not Found).
    """
    if runtime_config.is_vulnerable():
        # VULN: API8-Security-Misconfiguration - Sensitive debug info exposed
        flag = db.query(LabFlag).filter(LabFlag.category == "API8").first()
        flag_val = flag.flag_code if flag else None

        return {
            "status": "debug_enabled",
            "environment": settings.ENVIRONMENT,
            "python_executable": sys.executable,
            "python_version": sys.version,
            "sys_path": sys.path,
            "jwt_algorithm": settings.JWT_ALGORITHM,
            "mock_shipping_url": settings.MOCK_SHIPPING_URL,
            "database_url": settings.DATABASE_URL,
            "flag": flag_val,
        }
    else:
        # FIX: API8-Security-Misconfiguration - Disable verbose diagnostics
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Diagnostics and debug endpoints are disabled.",
        )


# ==============================================================================
# Scenario 8.2: Permissive Security Headers & CORS Check (API8)
# ==============================================================================
@router.get("/headers-check", summary="Security headers check (API8)")
def check_security_headers(response: Response):
    """Verifies response security headers.

    VULNERABLE MODE (API8-Security Misconfiguration):
    Omits essential defensive headers (X-Content-Type-Options, X-Frame-Options, CSP)
    and echoes permissive CORS settings.

    FIXED MODE:
    Applies strict defensive headers.
    """
    if runtime_config.is_vulnerable():
        # VULN: API8 - Missing security headers
        response.headers["Access-Control-Allow-Origin"] = "*"
        return {"status": "insecure_headers", "mode": "vulnerable"}
    else:
        # FIX: API8 - Hardened security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return {"status": "hardened_headers", "mode": "fixed"}
