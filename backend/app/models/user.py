"""
User model and in-memory user store for MVP and testing.
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel


class UserRole(str, Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class User(BaseModel):
    username: str
    role: UserRole = UserRole.analyst
    hashed_password: str
    disabled: bool = False


class UserStore:
    """Thread-safe in-memory store for users."""

    def __init__(self) -> None:
        self._users: Dict[str, User] = {}

    def add_user(self, user: User) -> None:
        self._users[user.username] = user

    def get_user(self, username: str) -> Optional[User]:
        return self._users.get(username)

    def list_users(self) -> List[User]:
        return list(self._users.values())

    def user_exists(self, username: str) -> bool:
        return username in self._users


user_store = UserStore()
