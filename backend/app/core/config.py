import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "AI Secure Data Intelligence Platform")
    environment: str = os.getenv("ENVIRONMENT", "development")

    # AI
    openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    ai_timeout_seconds: float = float(os.getenv("AI_TIMEOUT_SECONDS", "10"))

    # Input limits (defensive)
    max_content_bytes: int = int(os.getenv("MAX_CONTENT_BYTES", str(2 * 1024 * 1024)))
    max_lines: int = int(os.getenv("MAX_LOG_LINES", "20000"))

    # Rate limiting (in-memory)
    rate_limit_requests: int = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
    rate_limit_window_seconds: int = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

    # CORS
    cors_allow_origins: list[str] = field(default_factory=lambda: os.getenv("CORS_ALLOW_ORIGINS", "*").split(","))
    cors_allow_credentials: bool = os.getenv("CORS_ALLOW_CREDENTIALS", "false").lower() == "true"


settings = Settings()

