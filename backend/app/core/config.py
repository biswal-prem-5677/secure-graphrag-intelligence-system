"""
Secure GraphRAG Knowledge Intelligence System
Pydantic settings configuration — loaded from environment variables / .env file.

Production Safety:
  When ENVIRONMENT=production, the following fail fast with a clear error:
    - JWT_SECRET_KEY must be set via env and be >= 32 characters
    - DATABASE_URL must NOT be the default SQLite path
    - ALLOWED_ORIGINS must not contain localhost
    - DEFAULT_ADMIN_PASSWORD and DEFAULT_USER_PASSWORD must be provided
      via environment variables (not use the source-code defaults)
    - SEED_DEFAULT_USERS defaults to False in production
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --- Environment & Database ---
    ENVIRONMENT: Literal["development", "testing", "production"] = "development"
    DEBUG: bool = False
    DATABASE_URL: str = "sqlite:///./data/secure_graphrag.db"

    # --- LLM ---
    LLM_PROVIDER: Literal["mock", "gemini", "groq", "ollama", "openai", "multi"] = "mock"
    GOOGLE_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.5-flash"
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    LLM_TIMEOUT_SECONDS: int = 30

    # --- Neo4j ---
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "neo4j"
    SECRET_NEO4J_PASSWORD: str = ""

    # --- Redis ---
    REDIS_URL: str = ""
    USE_REDIS_RATE_LIMITER: bool = False

    # --- JWT ---
    JWT_SECRET_KEY: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 60

    @property
    def JWT_ACCESS_TOKEN_EXPIRE_MINUTES(self) -> int:
        return self.JWT_EXPIRY_MINUTES

    # --- Default users ---
    SEED_DEFAULT_USERS: bool = False
    DEFAULT_USER_USERNAME: str = "analyst"
    DEFAULT_USER_PASSWORD: str = ""
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_PASSWORD: str = ""

    @property
    def PORT(self) -> int:
        return self.API_PORT

    # --- API server ---
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

    @property
    def CORS_ORIGINS(self) -> list[str]:
        return self.cors_origins

    # --- Rate limiting ---
    RATE_LIMIT_REQUESTS: int = 30
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # --- Stripe ---
    STRIPE_SECRET_KEY: str = ""
    STRIPE_PUBLISHABLE_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""
    STRIPE_PRO_PRICE_ID: str = "price_threat_intel_pro_monthly"
    FREE_TIER_DAILY_LIMIT: int = 20
    PRO_TIER_DAILY_LIMIT: int = 200
    STRIPE_ENABLED: bool = False

    @property
    def FREE_TIER_DAILY_QUERY_LIMIT(self) -> int:
        return self.FREE_TIER_DAILY_LIMIT

    @property
    def PRO_TIER_DAILY_QUERY_LIMIT(self) -> int:
        return self.PRO_TIER_DAILY_LIMIT

    # --- Cache ---
    CACHE_TTL_SECONDS: int = 300
    CACHE_MAX_SIZE: int = 1000
    CACHE_MAXSIZE: int = 1000

    # --- Query limits ---
    MAX_QUERY_LENGTH: int = 1000
    MAX_GRAPH_DEPTH: int = 4
    MAX_GRAPH_RESULTS: int = 100
    MAX_CONTEXT_TOKENS: int = 2000
    QUERY_TIMEOUT_SECONDS: int = 30

    # --- Database connection pool (SQLAlchemy) ---
    DB_POOL_SIZE: int = 50
    DB_POOL_MAX_OVERFLOW: int = 20
    DB_POOL_RECYCLE_SECONDS: int = 3600

    @model_validator(mode="after")
    def validate_production_safety(self) -> "Settings":
        """In production mode, enforce that all required secrets are set and strong."""
        # Resolve Neo4j password from SECRET_NEO4J_PASSWORD if provided
        secret_neo = self.SECRET_NEO4J_PASSWORD or os.environ.get("SECRET_NEO4J_PASSWORD", "")
        if secret_neo:
            self.NEO4J_PASSWORD = secret_neo

        if self.ENVIRONMENT != "production":
            return self

        errors: list[str] = []

        # 1. JWT secret must be set and be cryptographically strong
        jwt_key = self.JWT_SECRET_KEY or os.environ.get("SECRET_JWT_KEY", "") or os.environ.get("JWT_SECRET_KEY", "")
        if not jwt_key or len(jwt_key) < 32:
            errors.append(
                "JWT_SECRET_KEY must be set to at least 32 characters in production. "
                "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
            )
        if not jwt_key or jwt_key in (
            "change-this-to-a-random-64-char-string-in-production",
            "production-secure-graphrag-jwt-secret-key-replace-with-env",
        ):
            errors.append("JWT_SECRET_KEY is still the default placeholder. Set a real secret.")

        # 2. DATABASE_URL must not be the default SQLite
        if self.DATABASE_URL == "sqlite:///./data/secure_graphrag.db":
            errors.append(
                "DATABASE_URL is still the default SQLite path. "
                "Set a PostgreSQL DATABASE_URL in production."
            )

        # 3. ALLOWED_ORIGINS must not contain localhost
        origins = self.cors_origins
        for origin in origins:
            if "localhost" in origin or "127.0.0.1" in origin:
                errors.append(
                    f"ALLOWED_ORIGINS contains localhost ('{origin}'). "
                    "Remove localhost origins in production."
                )

        # 4. Default passwords must be provided via env vars, not use source defaults
        admin_pw = self.DEFAULT_ADMIN_PASSWORD or os.environ.get("DEFAULT_ADMIN_PASSWORD", "")
        user_pw = self.DEFAULT_USER_PASSWORD or os.environ.get("DEFAULT_USER_PASSWORD", "")
        if not admin_pw:
            errors.append(
                "DEFAULT_ADMIN_PASSWORD must be set in production. "
                "Set a strong unique password via environment variable."
            )
        if not user_pw:
            errors.append(
                "DEFAULT_USER_PASSWORD must be set in production. "
                "Set a strong unique password via environment variable."
            )

    # 5. In production, require Redis for rate limiting
        if not self.REDIS_URL:
            errors.append(
                "REDIS_URL must be set in production for Redis-backed rate limiting."
            )

        # 6. Stripe keys must not be placeholder values (only when enabled)
        if self.STRIPE_ENABLED:
            if self.STRIPE_SECRET_KEY in ("sk_test_placeholder_key", ""):
                errors.append(
                    "STRIPE_SECRET_KEY is a placeholder or missing. Set a real key."
                )
            if self.STRIPE_WEBHOOK_SECRET in ("whsec_placeholder_secret", ""):
                errors.append(
                    "STRIPE_WEBHOOK_SECRET is a placeholder or missing. Set a real webhook secret."
                )

        if errors:
            from app.core.logging import get_logger
            get_logger("config").error("production_validation_failed", errors=errors)
            raise ValueError(
                "Production configuration errors:\n  • " + "\n  • ".join(errors)
            )

        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
