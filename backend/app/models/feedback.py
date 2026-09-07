"""
UserFeedback model and store for recording analyst quality ratings.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


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
    """Thread-safe feedback store with admin aggregation."""

    def __init__(self) -> None:
        self._feedbacks: List[UserFeedback] = []

    def submit_feedback(self, feedback: UserFeedback) -> None:
        self._feedbacks.append(feedback)

    def list_feedback(self, limit: int = 100) -> List[UserFeedback]:
        return sorted(self._feedbacks, key=lambda f: f.created_at, reverse=True)[:limit]

    def get_metrics(self) -> QualityMetrics:
        if not self._feedbacks:
            return QualityMetrics()
        total = len(self._feedbacks)
        avg_rating = sum(f.rating for f in self._feedbacks) / total
        hallucinations = sum(1 for f in self._feedbacks if f.is_hallucination)
        incompletes = sum(1 for f in self._feedbacks if f.is_incomplete)
        satisfied = sum(1 for f in self._feedbacks if f.rating >= 4)
        return QualityMetrics(
            total_feedback=total,
            average_rating=round(avg_rating, 2),
            hallucination_reports=hallucinations,
            incomplete_reports=incompletes,
            satisfaction_rate_percent=round(satisfied / total * 100, 1),
        )


feedback_store = FeedbackStore()
