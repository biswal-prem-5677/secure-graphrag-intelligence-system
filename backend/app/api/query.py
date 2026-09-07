"""
GraphRAG Investigation Query endpoint.
"""
import time
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, Request
from app.cache.cache import query_cache
from app.models.user import User
from app.schemas.schemas import QueryHistoryItem, QueryRequest, QueryResponse
from app.security.auth import get_current_user
from app.security.rate_limiter import RateLimiter, check_rate_limit
from app.services.query_service import query_service

router = APIRouter(prefix="/api/v1/query", tags=["GraphRAG Query"])
query_limiter = RateLimiter(max_requests=60, window_seconds=60)
_query_history: List[QueryHistoryItem] = []


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
        user_id=current_user.username,
        user_role=current_user.role.value,
    )
    time_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _query_history.append(
        QueryHistoryItem(
            query_id=resp.query_id,
            query=resp.query,
            timestamp=time_str,
            confidence=resp.confidence.value,
            operational_state=resp.operational_state.value,
        )
    )
    return resp


@router.get("/history", response_model=List[QueryHistoryItem])
async def get_history(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
) -> List[QueryHistoryItem]:
    """Retrieve recent queries submitted in the session."""
    return _query_history[-limit:]


@router.get("/cache/stats")
async def get_cache_stats(
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Return cache hit/miss statistics and memory usage."""
    return query_cache.get_stats()
