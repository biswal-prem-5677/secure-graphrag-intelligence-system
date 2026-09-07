"""
User personalization memory and session context store with database persistence and user isolation.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.db.repository import MemoryRepository


class UserMemoryItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    key: str
    value: str
    category: str = "preference"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SessionContext(BaseModel):
    session_id: str
    user_id: str
    last_entity: Optional[str] = None
    last_query: Optional[str] = None
    history: List[str] = Field(default_factory=list)


class UserMemoryStore:
    """Thread-safe persistent user memory store with user isolation and privacy controls."""

    def get_memories(self, user_id: str) -> List[UserMemoryItem]:
        """Return all memories for user from database."""
        db_mems = MemoryRepository.get_memories(user_id)
        return [
            UserMemoryItem(
                id=m.id,
                user_id=m.user_id,
                key=m.key,
                value=m.value,
                category=m.category,
                created_at=m.created_at,
            )
            for m in db_mems
        ]

    def add_or_update_memory(self, user_id: str, key: str, value: str, category: str = "preference") -> UserMemoryItem:
        db_mem = MemoryRepository.add_or_update(user_id, key, value, category)
        return UserMemoryItem(
            id=db_mem.id,
            user_id=db_mem.user_id,
            key=db_mem.key,
            value=db_mem.value,
            category=db_mem.category,
            created_at=db_mem.created_at,
        )

    def delete_memory(self, user_id: str, memory_id: str) -> bool:
        return MemoryRepository.delete(user_id, memory_id)

    def clear_all_for_user(self, user_id: str) -> None:
        """GDPR Right-to-be-Forgotten full memory purge."""
        MemoryRepository.clear_all(user_id)

    def get_session_context(self, session_id: str, user_id: str) -> SessionContext:
        db_ctx = MemoryRepository.get_session_context(session_id, user_id)
        try:
            hist = json.loads(db_ctx.history_json) if db_ctx.history_json else []
        except Exception:
            hist = []
        return SessionContext(
            session_id=db_ctx.session_id,
            user_id=db_ctx.user_id,
            last_entity=db_ctx.last_entity,
            last_query=db_ctx.last_query,
            history=hist,
        )

    def update_session_context(self, session_id: str, user_id: str, entity: Optional[str], query: str) -> None:
        MemoryRepository.update_session_context(session_id, user_id, entity, query)


memory_store = UserMemoryStore()
