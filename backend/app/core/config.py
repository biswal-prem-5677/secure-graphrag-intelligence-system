"""
Secure GraphRAG Knowledge Intelligence System
Pydantic settings configuration — loaded from environment variables / .env file.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

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
    NEO4J_PASSWORD: str = "graphrag_secure_2024"

    # --- JWT ---
    JWT_SECRET_KEY: str = "change-this-to-a-random-64-char-string-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 60

    @property
    def JWT_ACCESS_TOKEN_EXPIRE_MINUTES(self) -> int:
        return self.JWT_EXPIRY_MINUTES

    # --- Default users ---
    DEFAULT_USER_USERNAME: str = "analyst"
    DEFAULT_USER_PASSWORD: str = "SecureAnalyst2024!"
    DEFAULT_ADMIN_USERNAME: str = "admin"
    DEFAULT_ADMIN_PASSWORD: str = "SecureAdmin2024!"

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
    STRIPE_SECRET_KEY: str = "sk_test_placeholder_key"
    STRIPE_PUBLISHABLE_KEY: str = "pk_test_placeholder_key"
    STRIPE_WEBHOOK_SECRET: str = "whsec_placeholder_secret"
    STRIPE_PRO_PRICE_ID: str = "price_threat_intel_pro_monthly"
    FREE_TIER_DAILY_LIMIT: int = 20
    PRO_TIER_DAILY_LIMIT: int = 200

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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
