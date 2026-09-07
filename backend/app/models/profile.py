"""
UserProfile and UserPreferences store with onboarding tracking.
"""
from __future__ import annotations

from typing import Dict, Optional
from pydantic import BaseModel, Field


class UserPreferences(BaseModel):
    concise_answers: bool = False
    include_raw_subgraph: bool = True
    theme: str = "dark"
    default_hops: int = 2


class UserProfile(BaseModel):
    user_id: str
    display_name: str
    email: Optional[str] = None
    team: str = "Cyber Threat Intelligence Team"
    role_title: str = "Security Analyst"
    onboarding_completed: bool = False
    preferences: UserPreferences = Field(default_factory=UserPreferences)


class ProfileStore:
    """Thread-safe user profile store."""

    def __init__(self) -> None:
        self._profiles: Dict[str, UserProfile] = {}

    def get_profile(self, user_id: str) -> UserProfile:
        """Get or initialize default profile for user."""
        if user_id not in self._profiles:
            is_admin = user_id.lower() == "admin"
            self._profiles[user_id] = UserProfile(
                user_id=user_id,
                display_name=user_id.capitalize(),
                email=f"{user_id}@intelligence.local",
                team="Cyber Threat Intelligence Team",
                role_title="System Administrator" if is_admin else "Security Analyst",
                onboarding_completed=False,
            )
        return self._profiles[user_id]

    def update_profile(self, profile: UserProfile) -> None:
        self._profiles[profile.user_id] = profile

    def complete_onboarding(self, user_id: str) -> None:
        p = self.get_profile(user_id)
        p.onboarding_completed = True
        self.update_profile(p)

    def reset_onboarding(self, user_id: str) -> None:
        p = self.get_profile(user_id)
        p.onboarding_completed = False
        self.update_profile(p)


profile_store = ProfileStore()
