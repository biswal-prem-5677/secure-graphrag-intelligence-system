"""
User personalization memory and session context endpoints.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from app.models.memory import UserMemoryItem, memory_store
from app.models.user import User
from app.security.auth import get_current_user

router = APIRouter(prefix="/api/v1/memory", tags=["User Personalization & Memory"])


class AddMemoryRequest(BaseModel):
    key: str
    value: str
    category: str = "preference"


@router.get("", response_model=List[UserMemoryItem])
async def list_user_memories(
    current_user: User = Depends(get_current_user),
) -> List[UserMemoryItem]:
    """Retrieve all personalization memory items stored for the authenticated user."""
    return memory_store.get_memories(current_user.username)


@router.post("", response_model=UserMemoryItem)
async def create_user_memory(
    req: AddMemoryRequest,
    current_user: User = Depends(get_current_user),
) -> UserMemoryItem:
    """Store or update a user personalization preference."""
    return memory_store.add_or_update_memory(
        user_id=current_user.username, key=req.key, value=req.value, category=req.category
    )


@router.delete("/{memory_id}")
async def delete_user_memory(
    memory_id: str,
    current_user: User = Depends(get_current_user),
):
    """Delete an individual memory record."""
    deleted = memory_store.delete_memory(current_user.username, memory_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory item not found.")
    return {"message": "Memory item removed"}


@router.delete("/all/clear")
async def clear_all_memories(
    current_user: User = Depends(get_current_user),
):
    """GDPR Full user memory and session purge."""
    memory_store.clear_all_for_user(current_user.username)
    return {"message": "All user memories and session contexts cleared successfully."}
