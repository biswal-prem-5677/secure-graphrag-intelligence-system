"""
SavedInvestigation model and persistent store with database backing and strict multi-user isolation.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.db.repository import SavedInvestigationRepository
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


def _to_pydantic(db_inv) -> SavedInvestigation:
    try:
        gdata = json.loads(db_inv.graph_data_json) if db_inv.graph_data_json else {}
    except Exception:
        gdata = {}
    try:
        rpaths = json.loads(db_inv.relationship_paths_json) if db_inv.relationship_paths_json else []
    except Exception:
        rpaths = []
    try:
        erecs = json.loads(db_inv.evidence_records_json) if db_inv.evidence_records_json else []
    except Exception:
        erecs = []
    try:
        csources = json.loads(db_inv.cited_sources_json) if db_inv.cited_sources_json else []
    except Exception:
        csources = []

    conf_str = str(db_inv.confidence)
    if "ConfidenceLevel." in conf_str:
        conf_str = conf_str.replace("ConfidenceLevel.", "")
    try:
        conf_enum = ConfidenceLevel(conf_str)
    except Exception:
        conf_enum = ConfidenceLevel.HIGH

    return SavedInvestigation(
        id=db_inv.id,
        user_id=db_inv.user_id,
        query_id=db_inv.query_id,
        query=db_inv.query,
        title=db_inv.title,
        answer=db_inv.answer,
        confidence=conf_enum,
        confidence_explanation=db_inv.confidence_explanation,
        graph_data=GraphData(**gdata) if isinstance(gdata, dict) else GraphData(),
        relationship_paths=[RelationshipStep(**p) if isinstance(p, dict) else p for p in rpaths],
        evidence_records=[EvidenceRecord(**e) if isinstance(e, dict) else e for e in erecs],
        cited_sources=csources,
        saved_at=db_inv.saved_at,
    )


class SavedInvestigationStore:
    """Thread-safe persistent store for saved investigations with strict user isolation."""

    def save(self, user_id: str, record: SavedInvestigationCreate) -> SavedInvestigation:
        title = record.title or (record.query[:50] + "..." if len(record.query) > 50 else record.query)
        data = record.model_dump()
        data["title"] = title
        if hasattr(data.get("confidence"), "value"):
            data["confidence"] = data["confidence"].value
        elif "ConfidenceLevel." in str(data.get("confidence", "")):
            data["confidence"] = str(data["confidence"]).replace("ConfidenceLevel.", "")
        db_rec = SavedInvestigationRepository.create(user_id=user_id, record_data=data)
        return _to_pydantic(db_rec)


    def list_for_user(self, user_id: str) -> List[SavedInvestigation]:
        """Return all investigations belonging to user_id, sorted by newest first."""
        db_items = SavedInvestigationRepository.list_for_user(user_id)
        return [_to_pydantic(it) for it in db_items]

    def get(self, user_id: str, inv_id: str) -> Optional[SavedInvestigation]:
        """Get investigation if owned by user_id (anti-IDOR)."""
        db_item = SavedInvestigationRepository.get(user_id, inv_id)
        if not db_item:
            return None
        return _to_pydantic(db_item)

    def update_title(self, user_id: str, inv_id: str, new_title: str) -> Optional[SavedInvestigation]:
        db_item = SavedInvestigationRepository.update_title(user_id, inv_id, new_title)
        if not db_item:
            return None
        return _to_pydantic(db_item)

    def delete(self, user_id: str, inv_id: str) -> bool:
        return SavedInvestigationRepository.delete(user_id, inv_id)


saved_store = SavedInvestigationStore()
