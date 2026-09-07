"""
Saved Investigations bookmarking endpoints.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from app.models.saved import SavedInvestigation, SavedInvestigationCreate, saved_store
from app.models.user import User
from app.security.auth import get_current_user

router = APIRouter(prefix="/api/v1/saved", tags=["Saved Investigations"])


class RenameInvestigationRequest(BaseModel):
    title: str


@router.get("", response_model=List[SavedInvestigation])
async def list_saved_investigations(
    current_user: User = Depends(get_current_user),
) -> List[SavedInvestigation]:
    """List all saved investigations belonging to current user."""
    return saved_store.list_for_user(current_user.username)


@router.post("", response_model=SavedInvestigation)
async def save_investigation(
    req: SavedInvestigationCreate,
    current_user: User = Depends(get_current_user),
) -> SavedInvestigation:
    """Save an investigation record for future retrieval."""
    return saved_store.save(current_user.username, req)


@router.get("/{inv_id}", response_model=SavedInvestigation)
async def get_saved_investigation(
    inv_id: str,
    current_user: User = Depends(get_current_user),
) -> SavedInvestigation:
    """Retrieve a single saved investigation by ID with ownership check."""
    item = saved_store.get(current_user.username, inv_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved investigation not found")
    return item


@router.put("/{inv_id}", response_model=SavedInvestigation)
async def rename_saved_investigation(
    inv_id: str,
    req: RenameInvestigationRequest,
    current_user: User = Depends(get_current_user),
) -> SavedInvestigation:
    """Rename a saved investigation."""
    item = saved_store.update_title(current_user.username, inv_id, req.title)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved investigation not found")
    return item


@router.delete("/{inv_id}")
async def delete_saved_investigation(
    inv_id: str,
    current_user: User = Depends(get_current_user),
):
    """Delete a saved investigation record."""
    deleted = saved_store.delete(current_user.username, inv_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Saved investigation not found")
    return {"message": "Investigation successfully removed"}
