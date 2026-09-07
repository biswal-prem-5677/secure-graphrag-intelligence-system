"""
User personalization memory and session context store with user isolation and privacy controls.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


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
    """Thread-safe user memory store with user isolation and privacy deletion controls."""

    def __init__(self) -> None:
        self._memories: Dict[str, List[UserMemoryItem]] = {}
        self._sessions: Dict[str, SessionContext] = {}

    def get_memories(self, user_id: str) -> List[UserMemoryItem]:
        """Return all memories for user."""
        return self._memories.get(user_id, [])

    def add_or_update_memory(self, user_id: str, key: str, value: str, category: str = "preference") -> UserMemoryItem:
        items = self._memories.setdefault(user_id, [])
        for it in items:
            if it.key == key:
                it.value = value
                it.category = category
                return it
        new_item = UserMemoryItem(user_id=user_id, key=key, value=value, category=category)
        items.append(new_item)
        return new_item

    def delete_memory(self, user_id: str, memory_id: str) -> bool:
        items = self._memories.get(user_id, [])
        orig_len = len(items)
        self._memories[user_id] = [it for it in items if it.id != memory_id]
        return len(self._memories[user_id]) < orig_len

    def clear_all_for_user(self, user_id: str) -> None:
        """GDPR Right-to-be-Forgotten full memory purge."""
        self._memories.pop(user_id, None)
        # Clear session contexts
        keys_to_remove = [k for k, s in self._sessions.items() if s.user_id == user_id]
        for k in keys_to_remove:
            self._sessions.pop(k, None)

    def get_session_context(self, session_id: str, user_id: str) -> SessionContext:
        ctx = self._sessions.get(session_id)
        if not ctx or ctx.user_id != user_id:
            ctx = SessionContext(session_id=session_id, user_id=user_id)
            self._sessions[session_id] = ctx
        return ctx

    def update_session_context(self, session_id: str, user_id: str, entity: Optional[str], query: str) -> None:
        ctx = self.get_session_context(session_id, user_id)
        if entity:
            ctx.last_entity = entity
        ctx.last_query = query
        ctx.history.append(query)
        self._sessions[session_id] = ctx


memory_store = UserMemoryStore()
