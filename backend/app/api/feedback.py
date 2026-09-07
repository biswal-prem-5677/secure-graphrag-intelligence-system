"""
Investigation feedback and analyst rating endpoints.
"""
from typing import List
from fastapi import APIRouter, Depends
from app.models.feedback import UserFeedback, UserFeedbackCreate, feedback_store
from app.models.user import User
from app.security.auth import get_current_user

router = APIRouter(prefix="/api/v1/feedback", tags=["Investigation Feedback & Ratings"])


@router.post("")
async def submit_investigation_feedback(
    req: UserFeedbackCreate,
    current_user: User = Depends(get_current_user),
):
    """Submit user satisfaction rating on an investigation result."""
    feedback = UserFeedback(**req.model_dump(), user_id=current_user.username)
    feedback_store.submit_feedback(feedback)
    return {"message": "Feedback submitted successfully", "id": feedback.id}


@router.get("/recent", response_model=List[UserFeedback])
async def get_recent_feedback(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
) -> List[UserFeedback]:
    """Retrieve recent feedback submitted across the platform."""
    return feedback_store.list_feedback(limit=limit)
