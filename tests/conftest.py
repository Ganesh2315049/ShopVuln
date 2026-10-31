"""Shared test fixtures for ShopVuln."""

import pytest
from fastapi.testclient import TestClient
from app.database import Base, SessionLocal, engine
from app.main import app
from app.seed.seed_data import seed_database


@pytest.fixture(scope="session")
def client():
    """Provides a TestClient connected to the FastAPI application."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def clean_database_state():
    """Ensure every test executes against fresh deterministic seed data."""
    with SessionLocal() as db:
        seed_database(db, force_reset=True)
    yield
