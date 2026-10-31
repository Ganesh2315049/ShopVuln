"""Configuration management for ShopVuln."""

from typing import Any, Literal
import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "ShopVuln"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "training-lab"

    # Lab controls
    LAB_MODE: Literal["vulnerable", "fixed"] = "vulnerable"
    LAB_HINTS: Literal["off", "on"] = "off"

    # Server configuration
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Internal mock shipping & partner service
    MOCK_SHIPPING_HOST: str = "127.0.0.1"
    MOCK_SHIPPING_PORT: int = 9000
    MOCK_SHIPPING_URL: str = "http://127.0.0.1:9000"

    # Database
    DATABASE_URL: str = "sqlite:///./shopvuln.db"

    # Authentication & JWT (Synthetic lab secret only)
    JWT_SECRET: str = "shopvuln_synthetic_lab_jwt_secret_never_use_in_prod_2026"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 120

    # Prominent safety warning
    STARTUP_WARNING: str = (
        "*******************************************************************************\n"
        "*** [!] INTENTIONALLY VULNERABLE TRAINING LAB — DO NOT DEPLOY               ***\n"
        "*** This application contains deliberate security vulnerabilities for OWASP ***\n"
        "*** API Security Top 10 educational exercises only.                         ***\n"
        "*** Bound strictly to local interfaces. Do not expose to untrusted networks.***\n"
        "*******************************************************************************"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    def __setattr__(self, name: str, value: Any) -> None:
        super().__setattr__(name, value)
        if name == "LAB_MODE":
            try:
                from app.core.runtime import runtime_config

                if hasattr(runtime_config, "_mode") and runtime_config.get_mode() != value:
                    runtime_config.set_mode(value)
            except (ImportError, ValueError, AttributeError):
                pass


settings = Settings()
