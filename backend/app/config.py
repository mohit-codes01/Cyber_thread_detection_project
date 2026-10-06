"""
Application Configuration Module
Loads environment variables and application settings using pydantic-settings.
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


# Base Directory (project root)
BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """Application settings with environment variable overrides."""

    APP_NAME: str = "Cyber Threat Detector"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # Database
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'cyber_threat_detector.db'}"

    # JWT Authentication
    SECRET_KEY: str = "cyber-threat-detector-super-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours

    # Uploads & Storage
    MAX_UPLOAD_SIZE: int = 1024 * 1024 * 1024  # 1 GB (1024 MB)
    UPLOAD_DIR: str = str(BASE_DIR / "data" / "uploads")
    SAMPLE_DIR: str = str(BASE_DIR / "data" / "sample")
    REPORTS_DIR: str = str(BASE_DIR / "reports")
    MODELS_DIR: str = str(BASE_DIR / "models")

    # Threat Detection Scoring Weights (normalized sum = 1.0)
    WEIGHT_RULE: float = 0.35
    WEIGHT_ANOMALY: float = 0.25
    WEIGHT_ML: float = 0.25
    WEIGHT_INDICATOR: float = 0.15

    # Threat Intelligence API
    THREAT_INTEL_API_KEY: str = ""

    # CORS
    CORS_ORIGINS: str = "*"

    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

# Ensure critical runtime directories exist
for path_str in [settings.UPLOAD_DIR, settings.SAMPLE_DIR, settings.REPORTS_DIR, settings.MODELS_DIR]:
    Path(path_str).mkdir(parents=True, exist_ok=True)
