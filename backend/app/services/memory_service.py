"""
MemoryService: Resolves contextual anaphora, updates session context, and retrieves user formatting hints.
"""
from __future__ import annotations

import re
from typing import Optional, Tuple
from app.core.logging import get_logger
from app.models.memory import UserMemoryItem, memory_store

logger = get_logger("memory_service")


class MemoryService:
    """Safe memory retrieval and session context resolution."""

    def resolve_contextual_query(
        self, query: str, session_id: Optional[str] = None, user_id: Optional[str] = None
    ) -> Tuple[str, Optional[str]]:
        """Resolve pronouns ('it', 'they', 'this actor') using prior session context."""
        if not session_id or not user_id:
            return query, None

        ctx = memory_store.get_session_context(session_id, user_id)
        last_entity = ctx.last_entity

        if not last_entity:
            return query, None

        # Check for pronouns
        pattern = r"\b(it|they|this actor|this threat actor|this malware)\b"
        if re.search(pattern, query, re.IGNORECASE):
            resolved_query = re.sub(pattern, last_entity, query, count=1, flags=re.IGNORECASE)
            logger.info("contextual_anaphora_resolved", original=query, resolved=resolved_query, entity=last_entity)
            return resolved_query, last_entity

        return query, None

    def update_session(self, session_id: str, user_id: str, entity: Optional[str], query: str) -> None:
        """Update session-level context for continuous conversation."""
        memory_store.update_session_context(session_id, user_id, entity, query)

    def get_personalization_hint(self, user_id: str) -> Optional[str]:
        """Get presentation preferences (e.g. concise vs detailed) to shape formatting."""
        memories = memory_store.get_memories(user_id)
        for m in memories:
            if m.key == "result_density":
                if m.value.lower() == "compact":
                    return "Format response concisely."
                elif m.value.lower() == "detailed":
                    return "Include comprehensive details and transition paths."
        return None


memory_service = MemoryService()
