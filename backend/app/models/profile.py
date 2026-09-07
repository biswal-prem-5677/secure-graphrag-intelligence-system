"""
UserProfile and UserPreferences store backed by database persistence.
"""
from __future__ import annotations

import json
from typing import Dict, Optional
from pydantic import BaseModel, Field
from app.db.repository import ProfileRepository


class UserPreferences(BaseModel):
    concise_answers: bool = False
    include_raw_subgraph: bool = True
    theme: str = "light"
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
    """Thread-safe persistent user profile store."""

    def get_profile(self, user_id: str) -> UserProfile:
        """Get or initialize default profile for user."""
        is_admin = user_id.lower() == "admin"
        db_prof = ProfileRepository.get_or_create(
            user_id=user_id,
            display_name=user_id.capitalize(),
            email=f"{user_id}@intelligence.local",
            role_title="System Administrator" if is_admin else "Security Analyst",
        )
        try:
            prefs_dict = json.loads(db_prof.preferences_json) if db_prof.preferences_json else {}
            prefs = UserPreferences(**prefs_dict)
        except Exception:
            prefs = UserPreferences()

        return UserProfile(
            user_id=db_prof.user_id,
            display_name=db_prof.display_name,
            email=db_prof.email,
            team=db_prof.team,
            role_title=db_prof.role_title,
            onboarding_completed=db_prof.onboarding_completed,
            preferences=prefs,
        )

    def update_profile(self, profile: UserProfile) -> None:
        db_prof = ProfileRepository.get_or_create(profile.user_id)
        db_prof.display_name = profile.display_name
        db_prof.email = profile.email
        db_prof.team = profile.team
        db_prof.role_title = profile.role_title
        db_prof.onboarding_completed = profile.onboarding_completed
        db_prof.preferences_json = json.dumps(profile.preferences.model_dump())
        ProfileRepository.update(db_prof)

    def complete_onboarding(self, user_id: str) -> None:
        p = self.get_profile(user_id)
        p.onboarding_completed = True
        self.update_profile(p)

    def reset_onboarding(self, user_id: str) -> None:
        p = self.get_profile(user_id)
        p.onboarding_completed = False
        self.update_profile(p)


profile_store = ProfileStore()
