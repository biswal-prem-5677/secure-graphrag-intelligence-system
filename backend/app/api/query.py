"""
GraphRAG Investigation Query endpoint.
"""
import time
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, Request
from app.cache.cache import query_cache
from app.db.repository import QueryHistoryRepository
from app.models.user import User
from app.schemas.schemas import QueryHistoryItem, QueryRequest, QueryResponse
from app.security.auth import get_current_user
from app.security.rate_limiter import RateLimiter, check_rate_limit
from app.services.query_service import query_service

router = APIRouter(prefix="/api/v1/query", tags=["GraphRAG Query"])
query_limiter = RateLimiter(max_requests=60, window_seconds=60)


@router.post("", response_model=QueryResponse)
async def submit_query(
    req: QueryRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
) -> QueryResponse:
    """Execute end-to-end grounded GraphRAG query investigation."""
    check_rate_limit(request, query_limiter, username=current_user.username)
    resp = await query_service.execute_query(
        request=req,
        user_id=current_user.id,
        user_role=current_user.role.value,
    )
    # Persist to per-user history in DB
    QueryHistoryRepository.create(
        user_id=current_user.id,
        query_id=resp.query_id,
        query=resp.query,
        confidence=resp.confidence.value,
        operational_state=resp.operational_state.value,
    )
    return resp


@router.get("/history", response_model=List[QueryHistoryItem])
async def get_history(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
) -> List[QueryHistoryItem]:
    """Retrieve recent queries for the authenticated user."""
    entries = QueryHistoryRepository.list_for_user(user_id=current_user.id, limit=limit)
    return [
        QueryHistoryItem(
            query_id=e.query_id,
            query=e.query,
            timestamp=e.created_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            confidence=e.confidence,
            operational_state=e.operational_state,
        )
        for e in entries
    ]


@router.get("/cache/stats")
async def get_cache_stats(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Return cache hit/miss statistics and memory usage."""
    return query_cache.get_stats()
