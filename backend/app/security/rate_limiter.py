"""
Sliding-window rate limiter with Redis-backed storage for production,
and in-memory fallback for local development.

Production: Requires Redis. If Redis is unavailable, the limiter refuses to start.
Development: Falls back to in-memory if Redis URL is not set.
"""
from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional
from fastapi import HTTPException, Request, status
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("rate_limiter")

# Redis client — imported lazily to avoid crash in dev without Redis
_redis_client = None


def _get_redis_client():
    """Lazy Redis connection with environment-driven configuration."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    redis_url = settings.REDIS_URL
    if not redis_url:
        return None

    try:
        import redis
        # Use SSL if redis:// scheme indicates TLS (rediss://)
        ssl_opts = {}
        if redis_url.startswith("rediss://"):
            ssl_opts = {"ssl": True, "ssl_cert_reqs": "required"}
        _redis_client = redis.from_url(redis_url, decode_responses=True, **ssl_opts)
        _redis_client.ping()
        logger.info("redis_rate_limiter_connected", url=redis_url.split("@")[-1] if "@" in redis_url else "localhost")
        return _redis_client
    except Exception as e:
        logger.warning("redis_rate_limiter_connection_failed", error=str(e))
        return None


class RateLimiter:
    """Sliding-window rate limiter with Redis backend (production) or in-memory (dev)."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = Lock()

        # In production, always use Redis when REDIS_URL is available
        redis_url = settings.REDIS_URL
        if settings.ENVIRONMENT == "production":
            self._use_redis = bool(redis_url)
        else:
            self._use_redis = settings.USE_REDIS_RATE_LIMITER and bool(redis_url)

        self._redis = _get_redis_client() if self._use_redis else None

        if settings.ENVIRONMENT == "production" and not self._redis:
            raise RuntimeError(
                "Production rate limiting requires Redis. Set REDIS_URL to a reachable Redis instance."
            )

        if self._use_redis and self._redis:
            logger.info("rate_limiter_using_redis", max_requests=max_requests, window=window_seconds)
        else:
            logger.warning("rate_limiter_using_in_memory", message="Use Redis in production for multi-instance deployments")

    def _cleanup_in_memory(self, key: str, now: float) -> None:
        cutoff = now - self.window_seconds
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]

    def is_allowed(self, key: str) -> bool:
        """Check if a request from this key is allowed."""
        now = time.time()

        # Redis-backed sliding window
        if self._redis:
            try:
                redis_key = f"ratelimit:{key}"
                pipe = self._redis.pipeline()
                pipe.zremrangebyscore(redis_key, 0, now - self.window_seconds)
                pipe.zadd(redis_key, {str(now): now})
                pipe.zcard(redis_key)
                pipe.expire(redis_key, self.window_seconds)
                results = pipe.execute()
                count = results[2]
                return count <= self.max_requests
            except Exception as e:
                logger.error("redis_rate_limit_error", key=key, error=str(e))
                # In production, fail closed — deny request if Redis fails
                if settings.ENVIRONMENT == "production":
                    return False
                # In dev, fall back to in-memory
                pass

        # In-memory fallback
        with self._lock:
            self._cleanup_in_memory(key, now)
            if len(self._requests[key]) < self.max_requests:
                self._requests[key].append(now)
                return True
            return False

    def remaining(self, key: str) -> int:
        """Get remaining requests in the current window."""
        now = time.time()

        if self._redis:
            try:
                redis_key = f"ratelimit:{key}"
                self._redis.zremrangebyscore(redis_key, 0, now - self.window_seconds)
                count = self._redis.zcard(redis_key)
                return max(0, self.max_requests - count)
            except Exception:
                pass

        with self._lock:
            self._cleanup_in_memory(key, now)
            return max(0, self.max_requests - len(self._requests[key]))

    def reset_time(self, key: str) -> int:
        """Get the time until the oldest request expires."""
        now = time.time()

        if self._redis:
            try:
                redis_key = f"ratelimit:{key}"
                oldest = self._redis.zrange(redis_key, 0, 0, withscores=True)
                if oldest:
                    oldest_ts = oldest[0][1]
                    return max(0, int(self.window_seconds - (now - oldest_ts)))
            except Exception:
                pass

        with self._lock:
            if not self._requests[key]:
                return 0
            oldest = min(self._requests[key])
            return max(0, int(self.window_seconds - (now - oldest)))


def get_rate_limit_key(request: Request, username: Optional[str] = None) -> str:
    """Get rate limit key - prefer username, fall back to IP."""
    if username:
        return f"user:{username}"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take last IP (client) if there are multiple
        ip = forwarded.split(",")[-1].strip()
        # Remove port if present
        if ":" in ip:
            ip = ip.rsplit(":", 1)[0]
        return f"ip:{ip}"
    return f"ip:{request.client.host if request.client else 'unknown'}"


def check_rate_limit(request: Request, limiter: RateLimiter, username: Optional[str] = None) -> None:
    """Check rate limit and raise HTTPException if exceeded."""
    key = get_rate_limit_key(request, username)
    if not limiter.is_allowed(key):
        retry_after = limiter.reset_time(key)
        logger.warning("rate_limit_exceeded", key=key, retry_after=retry_after)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
