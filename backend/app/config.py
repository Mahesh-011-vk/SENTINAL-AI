from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = str(ROOT_DIR / "sentinelai.db")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    PROJECT_NAME: str = "SentinelAI Security Intelligence Platform"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = Field(default="development", description="Environment: development, staging, production")
    
    # Secret Key for JWT & Security signing
    SECRET_KEY: str = Field(
        default="09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7",
        description="JWT Secret key. Must be overridden with strong secret in production."
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 12  # 12 hours
    
    # Database
    DATABASE_URL: str = Field(
        default=f"sqlite:///{DEFAULT_DB_PATH}",
        description="Database URL. Default is SQLite for local run; PostgreSQL in production."
    )
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ]

    # AI Service Settings
    AI_PROVIDER: str = Field(default="mock", description="AI Provider: mock, openai, anthropic, or gemini")
    AI_API_KEY: Optional[str] = None
    AI_MODEL_NAME: str = "sentinel-security-reasoner"
    AI_TOKEN_BUDGET: int = 2000
    AI_REQUEST_TIMEOUT_SECONDS: int = 30

    # Risk Engine
    RISK_ENGINE_VERSION: str = "1.0.0"

    # Scanner Sandbox & Resource Limits
    SCAN_EXECUTION_TIMEOUT_SECONDS: int = 300
    MAX_ARCHIVE_SIZE_BYTES: int = 100 * 1024 * 1024  # 100 MB
    MAX_ARCHIVE_FILES: int = 5000
    ALLOW_LOCAL_TARGETS: bool = Field(
        default=False,
        description="Set to true ONLY in strictly isolated local test lab environments"
    )


settings = Settings()
