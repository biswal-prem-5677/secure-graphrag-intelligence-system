"""
User model and persistent user store with database backing.
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel
from app.db.repository import UserRepository


class UserRole(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class User(BaseModel):
    username: str
    role: UserRole = UserRole.analyst
    hashed_password: str
    disabled: bool = False
    email: Optional[str] = None


class UserStore:
    """Persistent store for users with thread-safe database backing."""

    def add_user(self, user: User) -> None:
        existing = UserRepository.get_by_username(user.username)
        if not existing:
            UserRepository.create(
                username=user.username,
                hashed_password=user.hashed_password,
                email=user.email,
                role=user.role.value,
            )

    def get_user(self, username: str) -> Optional[User]:
        db_user = UserRepository.get_by_username(username)
        if not db_user:
            return None
        return User(
            username=db_user.username,
            role=UserRole(db_user.role),
            hashed_password=db_user.hashed_password,
            disabled=db_user.disabled,
            email=db_user.email,
        )

    def list_users(self) -> List[User]:
        db_users = UserRepository.list_all()
        return [
            User(
                username=u.username,
                role=UserRole(u.role),
                hashed_password=u.hashed_password,
                disabled=u.disabled,
                email=u.email,
            )
            for u in db_users
        ]

    def user_exists(self, username: str) -> bool:
        return UserRepository.get_by_username(username) is not None


user_store = UserStore()
