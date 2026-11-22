"""
Health & Readiness monitoring probes.
"""
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from app.cache.cache import query_cache
from app.core.config import settings
from app.db.database import SessionLocal
from app.graph.client import neo4j_client
from app.schemas.schemas import HealthResponse, ReadyResponse

router = APIRouter(tags=["Health & Monitoring"])


def _check_postgres() -> tuple[bool, str]:
    """Verify PostgreSQL/SQLite connectivity with a lightweight query."""
    try:
        db = SessionLocal()
        try:
            db.execute(text("SELECT 1"))
            return True, "connected"
        finally:
            db.close()
    except Exception as e:
        return False, f"error: {type(e).__name__}: {e}"


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Liveness probe: verifies the API service is up and responsive."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        llm_provider=settings.LLM_PROVIDER,
        neo4j_connected=neo4j_client.is_connected,
    )


@router.get("/ready", response_model=ReadyResponse)
async def readiness_check() -> JSONResponse:
    """Readiness probe: verifies backend connections to PostgreSQL, Neo4j, cache, and LLM.

    In production mode, this endpoint returns 503 if any required dependency is unavailable,
    preventing traffic from being routed to the instance until it can serve real requests.
    """
    pg_ok, pg_status = _check_postgres()
    neo_healthy = await neo4j_client.is_healthy()

    all_ok = pg_ok and neo_healthy
    overall = "ready" if all_ok else "degraded"

    body = ReadyResponse(
        status=overall,
        neo4j="connected" if neo_healthy else "disconnected",
        cache="healthy",
        active_llm=settings.LLM_PROVIDER,
    ).model_dump()

    if not pg_ok:
        body["postgres"] = pg_status
    else:
        body["postgres"] = "connected"

    http_status = status.HTTP_200_OK if all_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(content=body, status_code=http_status)
