"""
Secure GraphRAG Knowledge Intelligence System - Main Application Entrypoint.
Production-grade GraphRAG cybersecurity threat-intelligence investigation platform with grounded reasoning, multi-hop traversal, and explainable confidence scoring.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator
import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api import (
    admin_router,
    auth_router,
    billing_router,
    entities_router,
    feedback_router,
    health_router,
    memory_router,
    observability_router,
    profile_router,
    query_router,
    saved_router,
)
from app.cache.cache import query_cache
from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from app.core.middleware import RequestIDMiddleware, SecurityHeadersMiddleware, TimingMiddleware
from app.core.telemetry import telemetry_store
from app.db.database import init_db
from app.graph.client import neo4j_client
from app.security.auth import seed_default_users

setup_logging()
logger = get_logger("app.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifecycle event handler for startup and shutdown actions."""
    logger.info("application_starting", version="1.0.0", env=settings.ENVIRONMENT)
    init_db()
    seed_default_users()

    # Attempt connection to Neo4j
    connected = await neo4j_client.connect()
    if connected:
        logger.info("neo4j_initialization_success")
    else:
        logger.warning(
            "neo4j_initialization_delayed",
            msg=f"Ensure Neo4j is running on {settings.NEO4J_URI} or operating in offline fallback mode.",
        )

    yield

    logger.info("application_shutting_down")
    await neo4j_client.close()


app = FastAPI(
    title="Secure GraphRAG Knowledge Intelligence System",
    description="Production-grade GraphRAG cybersecurity threat-intelligence investigation platform with grounded reasoning, multi-hop traversal, and explainable confidence scoring.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom Middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(TimingMiddleware)
app.add_middleware(RequestIDMiddleware)


# Exception Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    logger.warning("request_validation_failed", errors=exc.errors(), url=str(request.url))
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error": "Validation Error", "detail": "Invalid payload", "errors": exc.errors()},
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    req_id = getattr(request.state, "request_id", "unknown")
    logger.error("unhandled_exception", exc=str(exc), request_id=req_id)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "detail": "An unexpected error occurred. Reference the request ID with support.",
            "request_id": req_id,
        },
    )


# Include Routers
app.include_router(health_router)
app.include_router(auth_router)
app.include_router(query_router)
app.include_router(entities_router)
app.include_router(billing_router)
app.include_router(feedback_router)
app.include_router(memory_router)
app.include_router(profile_router)
app.include_router(saved_router)
app.include_router(admin_router)
app.include_router(observability_router)


@app.get("/metrics", tags=["Observability"])
async def get_metrics() -> JSONResponse:
    """Prometheus-compatible real-time performance and reliability metrics."""
    metrics = telemetry_store.get_metrics()
    cache_stats = query_cache.get_stats()
    metrics["cache"] = cache_stats
    return JSONResponse(content=metrics)


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.PORT, reload=settings.DEBUG)
