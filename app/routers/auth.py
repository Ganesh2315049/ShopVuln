"""Authentication endpoints: login, token issuance, profile check, and API2 Broken Authentication scenarios."""

from datetime import datetime, timedelta, timezone
import secrets
from typing import Dict, Optional
import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.config import settings
from app.core.runtime import runtime_config
from app.core.security import (
    create_access_token,
    get_current_user,
    hash_password,
    require_admin,
    require_seller,
    verify_password,
)
from app.database import get_db
from app.models import LabFlag, User
from app.schemas.auth import LoginRequest, TokenResponse, UserResponse

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication & API2"])

# In-memory store for password reset tokens: username -> {"token": str, "expires": datetime}
_reset_tokens_db: Dict[str, dict] = {}


class SessionExchangeRequest(BaseModel):
    token: str


class ForgotPasswordRequest(BaseModel):
    username_or_email: str


class ResetPasswordRequest(BaseModel):
    username_or_email: str
    reset_token: str
    new_password: str


@router.post("/login", response_model=TokenResponse, summary="User login with JSON body")
def login_json(payload: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate with username or email and password."""
    user = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.username))
        .first()
    )

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials: username/email or password incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    token = create_access_token(
        data={"sub": str(user.id), "username": user.username, "role": user.role}
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user.role,
        username=user.username,
        user_id=user.id,
    )


@router.post("/token", summary="OAuth2 password form login (for Swagger UI)")
def login_oauth(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """OAuth2 password form login compliant with Swagger UI 'Authorize' button."""
    user = (
        db.query(User)
        .filter((User.username == form_data.username) | (User.email == form_data.username))
        .first()
    )

    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        data={"sub": str(user.id), "username": user.username, "role": user.role}
    )

    return {"access_token": token, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse, summary="Get current authenticated user profile")
def get_me(current_user: User = Depends(get_current_user)):
    """Return profile details of current user from valid JWT token."""
    return current_user


@router.get("/admin-check", summary="Admin-only role check endpoint")
def admin_only_check(current_user: User = Depends(require_admin)):
    """Protected endpoint accessible only to administrators."""
    return {
        "status": "authorized",
        "user_id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "message": "Welcome, administrator.",
    }


@router.get("/seller-check", summary="Seller-only role check endpoint")
def seller_only_check(current_user: User = Depends(require_seller)):
    """Protected endpoint accessible to sellers and administrators."""
    return {
        "status": "authorized",
        "user_id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "message": "Welcome, verified merchant/seller.",
    }


# ==============================================================================
# Scenario 2.1: JWT Verification Flaw / Unsigned Token Acceptance
# ==============================================================================
@router.post("/session-exchange", summary="Legacy session exchange (API2: Broken Authentication)")
def session_exchange(payload: SessionExchangeRequest, db: Session = Depends(get_db)):
    """Exchanges an external or legacy JWT for an active session.

    VULNERABLE MODE (API2-Broken-Auth):
    Accepts unsigned tokens ('alg': 'none') or skips cryptographic signature verification.
    If an attacker submits an unsigned token with sub='5' (admin), an admin session is granted.

    FIXED MODE:
    Strictly enforces signature verification with HS256 and the shared lab secret.
    """
    if runtime_config.is_vulnerable():
        # VULN: API2-Broken-Auth - Skipping signature check or allowing alg: none
        try:
            # Decode unverified
            unverified_claims = jwt.decode(payload.token, options={"verify_signature": False})
            user_id = int(unverified_claims.get("sub", 0))
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                raise HTTPException(status_code=401, detail="User in token does not exist")

            # Check if attacker forged an administrative identity
            flag_val = None
            if user.role == "admin":
                flag = db.query(LabFlag).filter(LabFlag.category == "API2").first()
                if flag:
                    flag_val = flag.flag_code

            # Issue valid session
            new_token = create_access_token(
                data={"sub": str(user.id), "username": user.username, "role": user.role}
            )
            return {
                "status": "session_exchanged",
                "access_token": new_token,
                "role": user.role,
                "username": user.username,
                "flag": flag_val,
            }
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"Invalid token format: {str(e)}")
    else:
        # FIX: API2-Broken-Auth - Strictly verify signature with HMAC-SHA256
        try:
            verified_claims = jwt.decode(
                payload.token,
                settings.JWT_SECRET,
                algorithms=["HS256"],
                options={"verify_signature": True},
            )
            user_id = int(verified_claims.get("sub", 0))
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                raise HTTPException(status_code=401, detail="User in token does not exist")

            new_token = create_access_token(
                data={"sub": str(user.id), "username": user.username, "role": user.role}
            )
            return {
                "status": "session_exchanged",
                "access_token": new_token,
                "role": user.role,
                "username": user.username,
                "flag": None,
            }
        except jwt.PyJWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Signature verification failed: invalid or unsigned token rejected",
            )


# ==============================================================================
# Scenario 2.2: Predictable Password Reset PIN
# ==============================================================================
@router.post("/forgot-password", summary="Request password reset token (API2: Broken Authentication)")
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Initiates password reset for a given username or email."""
    user = (
        db.query(User)
        .filter((User.username == payload.username_or_email) | (User.email == payload.username_or_email))
        .first()
    )
    if not user:
        # In both modes, avoid account enumeration or give standard prompt
        return {"message": "If the account exists, reset instructions have been dispatched."}

    if runtime_config.is_vulnerable():
        # VULN: API2-Broken-Auth - Predictable 4-digit PIN based on deterministic user ID formula
        predictable_pin = f"{(user.id * 1111) % 10000:04d}"
        _reset_tokens_db[user.username] = {
            "token": predictable_pin,
            "expires": datetime.now(timezone.utc) + timedelta(minutes=30),
        }
        # In vulnerable mode, leak the PIN in the debug response message for testing
        return {
            "message": "Password reset initiated.",
            "debug_pin": predictable_pin,
            "note": "DEBUG: Predictable reset token generated for lab exercise",
        }
    else:
        # FIX: API2-Broken-Auth - Cryptographically secure 32-byte URL-safe token
        secure_token = secrets.token_urlsafe(32)
        _reset_tokens_db[user.username] = {
            "token": secure_token,
            "expires": datetime.now(timezone.utc) + timedelta(minutes=15),
        }
        return {"message": "If the account exists, reset instructions have been dispatched."}


@router.post("/reset-password", summary="Execute password reset (API2: Broken Authentication)")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Reset password using generated token."""
    user = (
        db.query(User)
        .filter((User.username == payload.username_or_email) | (User.email == payload.username_or_email))
        .first()
    )
    if not user:
        raise HTTPException(status_code=400, detail="Invalid user or reset token")

    record = _reset_tokens_db.get(user.username)
    if not record or record["expires"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Reset token expired or non-existent")

    if record["token"] != payload.reset_token:
        raise HTTPException(status_code=400, detail="Invalid reset token")

    # Update password
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    del _reset_tokens_db[user.username]

    flag_val = None
    if runtime_config.is_vulnerable():
        flag = db.query(LabFlag).filter(LabFlag.category == "API2").first()
        if flag:
            flag_val = flag.flag_code

    return {
        "status": "success",
        "message": f"Password for {user.username} successfully updated.",
        "flag": flag_val,
    }
