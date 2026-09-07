"""
SQLAlchemy database engine and session configuration.
Seamlessly handles PostgreSQL in production and SQLite for local development and CI testing.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("database")

def get_database_url() -> str:
    url = getattr(settings, "DATABASE_URL", None)
    if not url:
        url = os.environ.get("DATABASE_URL", "sqlite:///./data/secure_graphrag.db")
    # Convert postgres:// to postgresql:// for SQLAlchemy 2.0 compatibility
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url

db_url = get_database_url()

connect_args = {}
if db_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    # Ensure local directory exists for SQLite
    if "///" in db_url and not db_url.endswith(":memory:"):
        db_path = db_url.split("///")[-1]
        parent = Path(db_path).parent
        parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    db_url,
    connect_args=connect_args,
    pool_pre_ping=True if not db_url.startswith("sqlite") else False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db() -> None:
    """Initialize database tables."""
    from app.db.models import Base
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("database_tables_initialized", db_type="sqlite" if db_url.startswith("sqlite") else "postgresql")
    except Exception as e:
        logger.error("database_initialization_failed", error=str(e))
        raise
