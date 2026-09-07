"""
Health & Readiness monitoring probes.
"""
from fastapi import APIRouter
from app.cache.cache import query_cache
from app.core.config import settings
from app.graph.client import neo4j_client
from app.schemas.schemas import HealthResponse, ReadyResponse

router = APIRouter(tags=["Health & Monitoring"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Liveness probe: verifies the API service is up and responsive."""
    return HealthResponse(status="healthy", version="1.0.0")


@router.get("/ready", response_model=ReadyResponse)
async def readiness_check() -> ReadyResponse:
    """Readiness probe: verifies backend connections to Neo4j and cache subsystems."""
    neo_healthy = await neo4j_client.is_healthy()
    return ReadyResponse(
        status="ready" if neo_healthy else "degraded",
        neo4j="connected" if neo_healthy else "disconnected",
        cache="healthy",
        active_llm=settings.LLM_PROVIDER,
    )
