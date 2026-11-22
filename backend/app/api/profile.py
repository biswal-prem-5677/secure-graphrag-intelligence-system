"""
User Profile and Preferences API endpoints.
"""
import re
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator
from app.models.profile import UserPreferences, UserProfile, profile_store
from app.models.user import User
from app.security.auth import get_current_user

router = APIRouter(prefix="/api/v1/profile", tags=["User Profile & Preferences"])


class UpdateProfileRequest(BaseModel):
    display_name: Optional[str] = None
    email: Optional[str] = None
    team: Optional[str] = None
    role_title: Optional[str] = None
    preferences: Optional[UserPreferences] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_pattern, v):
            raise ValueError("Invalid email format")
        return v


@router.get("", response_model=UserProfile)
async def get_profile(
    current_user: User = Depends(get_current_user),
) -> UserProfile:
    """Retrieve profile and onboarding status for current authenticated user."""
    return profile_store.get_profile(current_user.id)


@router.put("", response_model=UserProfile)
async def update_profile(
    req: UpdateProfileRequest,
    current_user: User = Depends(get_current_user),
) -> UserProfile:
    """Update profile and preference settings."""
    profile = profile_store.get_profile(current_user.id)
    if req.display_name is not None:
        profile.display_name = req.display_name
    if req.email is not None:
        profile.email = req.email
    if req.team is not None:
        profile.team = req.team
    if req.role_title is not None:
        profile.role_title = req.role_title
    if req.preferences is not None:
        profile.preferences = req.preferences
    profile_store.update_profile(profile)
    return profile


@router.post("/onboarding-complete")
async def complete_onboarding(current_user: User = Depends(get_current_user)):
    """Mark onboarding tour as complete for current user."""
    profile_store.complete_onboarding(current_user.id)
    return {"status": "completed"}


@router.post("/reset-onboarding")
async def reset_onboarding(current_user: User = Depends(get_current_user)):
    """Reset onboarding flag to replay product tour."""
    profile_store.reset_onboarding(current_user.id)
    return {"status": "reset"}
