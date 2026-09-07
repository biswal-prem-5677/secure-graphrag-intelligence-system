"""
SavedInvestigation model and store for bookmarking investigation findings with user isolation.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.schemas import ConfidenceLevel, EvidenceRecord, GraphData, RelationshipStep


class SavedInvestigationCreate(BaseModel):
    query_id: str
    query: str
    title: Optional[str] = None
    answer: str
    confidence: ConfidenceLevel
    confidence_explanation: str
    graph_data: GraphData = Field(default_factory=GraphData)
    relationship_paths: List[RelationshipStep] = Field(default_factory=list)
    evidence_records: List[EvidenceRecord] = Field(default_factory=list)
    cited_sources: List[str] = Field(default_factory=list)


class SavedInvestigation(SavedInvestigationCreate):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    saved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SavedInvestigationStore:
    """Thread-safe store for saved investigations with user isolation."""

    def __init__(self) -> None:
        self._saved: Dict[str, List[SavedInvestigation]] = {}

    def save(self, user_id: str, record: SavedInvestigationCreate) -> SavedInvestigation:
        title = record.title or (record.query[:50] + "..." if len(record.query) > 50 else record.query)
        saved_rec = SavedInvestigation(
            **record.model_dump(exclude={"title"}),
            title=title,
            user_id=user_id,
        )
        self._saved.setdefault(user_id, []).append(saved_rec)
        return saved_rec

    def list_for_user(self, user_id: str) -> List[SavedInvestigation]:
        """Return all investigations belonging to user_id, sorted by newest first."""
        items = self._saved.get(user_id, [])
        return sorted(items, key=lambda x: x.saved_at, reverse=True)

    def get(self, user_id: str, inv_id: str) -> Optional[SavedInvestigation]:
        """Get investigation if owned by user_id."""
        for item in self._saved.get(user_id, []):
            if item.id == inv_id:
                return item
        return None

    def update_title(self, user_id: str, inv_id: str, new_title: str) -> Optional[SavedInvestigation]:
        item = self.get(user_id, inv_id)
        if item:
            item.title = new_title
        return item

    def delete(self, user_id: str, inv_id: str) -> bool:
        items = self._saved.get(user_id, [])
        orig_len = len(items)
        self._saved[user_id] = [it for it in items if it.id != inv_id]
        return len(self._saved[user_id]) < orig_len


saved_store = SavedInvestigationStore()
