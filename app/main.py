"""ShopVuln main FastAPI application entrypoint."""

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.core.runtime import runtime_config
from app.database import Base, SessionLocal, engine
from datetime import datetime, timezone
import json
import time
from app.routers import (
    admin,
    auth,
    cart,
    checkout,
    health,
    lab,
    legacy,
    orders,
    products,
    shipping,
    system,
    users,
    webhooks,
)
from app.seed.seed_data import seed_database

# Configure base logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("shopvuln")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure logs directory exists
    logs_dir = Path("./logs")
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Initialize SQLite database schema
    Base.metadata.create_all(bind=engine)

    # Populate synthetic seed data if needed
    with SessionLocal() as db_session:
        seed_database(db_session, force_reset=False)

    # Print prominent safety warning banner
    sys.stderr.write(f"\n{settings.STARTUP_WARNING}\n\n")
    logger.warning("ShopVuln initialized in '%s' mode.", runtime_config.get_mode().upper())
    yield
    logger.info("ShopVuln shutting down.")


def create_app() -> FastAPI:
    tags_metadata = [
        {
            "name": "Lab Mode Control",
            "description": (
                "Interactive runtime controls for switching between Vulnerable and Fixed modes. "
                "Use `GET /lab/mode` to inspect the current mode, and `PUT /lab/mode` (with an authenticated "
                "admin Bearer token) to dynamically switch modes without restarting containers."
            ),
        },
        {
            "name": "Lab Management & CTF",
            "description": "Lab reset, hints catalog, scoreboard, and flag submission endpoints.",
        },
    ]

    app = FastAPI(
        title="ShopVuln — OWASP API Security Training Lab",
        description=(
            "A realistic, intentionally vulnerable e-commerce REST API designed for "
            "practicing the OWASP API Security Top 10 (2023).\n\n"
            "**WARNING: INTENTIONALLY VULNERABLE TRAINING LAB — DO NOT DEPLOY**\n\n"
            "### Lab Mode Control\n"
            "Use the **Lab Mode Control** section below to check (`GET /lab/mode`) or switch (`PUT /lab/mode`) "
            "between **vulnerable** and **fixed** modes at runtime. Switching modes requires admin authentication."
        ),
        version=settings.APP_VERSION,
        openapi_tags=tags_metadata,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Allow local development and testing origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Structured JSON access logging middleware
    @app.middleware("http")
    async def json_access_log_middleware(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time_ms = round((time.time() - start_time) * 1000, 2)

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query),
            "status_code": response.status_code,
            "client_ip": request.client.host if request.client else "unknown",
            "duration_ms": process_time_ms,
            "lab_mode": runtime_config.get_mode(),
        }

        try:
            with open("./logs/access.log", "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception:
            pass

        return response

    # Register routers
    app.include_router(health.router)
    app.include_router(lab.router)
    app.include_router(auth.router)
    app.include_router(orders.router)
    app.include_router(users.router)
    app.include_router(products.router)
    app.include_router(cart.router)
    app.include_router(admin.router)
    app.include_router(checkout.router)
    app.include_router(shipping.router)
    app.include_router(system.router)
    app.include_router(legacy.router)
    app.include_router(webhooks.router)

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
    )
