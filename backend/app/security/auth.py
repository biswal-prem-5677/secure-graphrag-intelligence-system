"""
Authentication and authorization utilities: native bcrypt hashing, JWT issuance, and user dependencies.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from app.core.config import settings
from app.core.logging import get_logger
from app.models.user import User, UserRole, user_store

logger = get_logger("security_auth")

security_scheme = HTTPBearer(auto_error=False)


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using native bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain_password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception as e:
        logger.warning("password_verification_error", error=str(e))
        return False


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
) -> User:
    """FastAPI dependency: extract and validate the current user from JWT."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    username: str = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = user_store.get_user(username)
    if not user or user.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """FastAPI dependency: require admin role."""
    if current_user.role != UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required",
        )
    return current_user


def seed_default_users() -> None:
    """Seed admin and analyst users into user_store if enabled and absent."""
    if not getattr(settings, "SEED_DEFAULT_USERS", True):
        logger.info("seed_default_users_skipped_by_config")
        return

    try:
        from app.db.database import init_db
        init_db()
    except Exception as e:
        logger.warning("seed_default_users_init_db_error", error=str(e))
        return

    admin_pw = settings.DEFAULT_ADMIN_PASSWORD
    user_pw = settings.DEFAULT_USER_PASSWORD

    try:
        if not user_store.user_exists("admin"):
            user_store.add_user(
                User(
                    username="admin",
                    role=UserRole.admin,
                    hashed_password=hash_password(admin_pw),
                    disabled=False,
                )
            )
            logger.info("default_admin_created")

        if not user_store.user_exists("analyst"):
            user_store.add_user(
                User(
                    username="analyst",
                    role=UserRole.analyst,
                    hashed_password=hash_password(user_pw),
                    disabled=False,
                )
            )
            logger.info("default_user_created")
    except Exception as e:
        logger.warning("seed_default_users_failed", error=str(e))


# Seed on import if database is available
try:
    seed_default_users()
except Exception:
    pass

