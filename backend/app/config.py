"""
VulnScan Lite - Configuration Settings Management
Uses Pydantic Settings for environment-driven, production-safe configuration.
"""
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application & Environment
    APP_NAME: str = "VulnScan Lite"
    APP_ENV: str = "development"  # "development", "testing", "production"
    DEBUG: bool = False
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    SECRET_KEY: str = "default-development-secret-key-change-in-production"

    # Database
    DATABASE_URL: str = "sqlite:///./vulnscan.db"

    # Redis / Celery Task Queue
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"

    # Scanner Operational & Safety Bounds
    SCANNER_TIMEOUT_SECONDS: int = 10
    SCANNER_MAX_REDIRECTS: int = 5
    SCANNER_MAX_RESPONSE_BYTES: int = 5 * 1024 * 1024  # 5 MB

    # API Request & Abuse Guardrails
    MAX_REQUEST_BODY_BYTES: int = 64 * 1024  # 64 KB max payload size
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_SCAN_CREATION_LIMIT: int = 10  # 10 scan requests per window
    RATE_LIMIT_SCAN_CREATION_WINDOW: int = 60  # 60 seconds

    # Security Headers & TLS Configuration
    ENABLE_HSTS: bool = False  # Set to True only when deployed over real HTTPS

    # CORS Allowed Origins
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
