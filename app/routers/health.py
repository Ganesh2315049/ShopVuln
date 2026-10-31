"""Health and root discovery endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter
from app.config import settings
from app.core.runtime import runtime_config

router = APIRouter(tags=["System & Health"])


@router.get("/health", summary="Health check endpoint")
async def health_check():
    """Returns the operational status, lab mode, and hints configuration."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "mode": runtime_config.get_mode(),
        "hints_enabled": settings.LAB_HINTS == "on",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "warning": "INTENTIONALLY VULNERABLE TRAINING LAB — DO NOT DEPLOY",
    }


@router.get("/", summary="Lab root discovery")
async def root():
    """Returns welcome message, docs location, and safety statement."""
    return {
        "message": "Welcome to ShopVuln - OWASP API Security Top 10 (2023) Training Lab",
        "version": settings.APP_VERSION,
        "mode": runtime_config.get_mode(),
        "docs_url": "/docs",
        "health_url": "/health",
        "safety_notice": "INTENTIONALLY VULNERABLE TRAINING LAB — DO NOT DEPLOY. Bound to localhost only.",
    }
