"""
UserFeedback model and persistent store for recording analyst quality ratings.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.db.database import SessionLocal
from app.db.models import DBFeedback
from app.db.repository import FeedbackRepository


class UserFeedbackCreate(BaseModel):
    query_id: str
    query: str
    rating: int = Field(..., ge=1, le=5)
    comment: Optional[str] = None
    is_hallucination: bool = False
    is_incomplete: bool = False


class UserFeedback(UserFeedbackCreate):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class QualityMetrics(BaseModel):
    total_feedback: int = 0
    average_rating: float = 0.0
    hallucination_reports: int = 0
    incomplete_reports: int = 0
    satisfaction_rate_percent: float = 100.0


class FeedbackStore:
    """Thread-safe persistent feedback store with admin aggregation."""

    def submit_feedback(self, feedback: UserFeedback) -> None:
        FeedbackRepository.create(
            user_id=feedback.user_id,
            query_id=feedback.query_id,
            query=feedback.query,
            rating=feedback.rating,
            comment=feedback.comment,
            is_hallucination=feedback.is_hallucination,
            is_incomplete=feedback.is_incomplete,
        )

    def list_feedback(self, limit: int = 100) -> List[UserFeedback]:
        db_items = FeedbackRepository.list_all(limit=limit)
        return [
            UserFeedback(
                id=f.id,
                user_id=f.user_id,
                query_id=f.query_id,
                query=f.query,
                rating=f.rating,
                comment=f.comment,
                is_hallucination=f.is_hallucination,
                is_incomplete=f.is_incomplete,
                created_at=f.created_at,
            )
            for f in db_items
        ]

    def get_metrics(self) -> QualityMetrics:
        feedbacks = self.list_feedback(limit=1000)
        if not feedbacks:
            return QualityMetrics()
        total = len(feedbacks)
        avg_rating = sum(f.rating for f in feedbacks) / total
        hallucinations = sum(1 for f in feedbacks if f.is_hallucination)
        incompletes = sum(1 for f in feedbacks if f.is_incomplete)
        satisfied = sum(1 for f in feedbacks if f.rating >= 4)
        return QualityMetrics(
            total_feedback=total,
            average_rating=round(avg_rating, 2),
            hallucination_reports=hallucinations,
            incomplete_reports=incompletes,
            satisfaction_rate_percent=round(satisfied / total * 100, 1),
        )


feedback_store = FeedbackStore()
