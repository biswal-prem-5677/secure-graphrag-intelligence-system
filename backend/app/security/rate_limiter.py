"""
Sliding-window rate limiter with per-user and per-IP tracking.
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


class RateLimiter:
    """In-memory sliding-window rate limiter."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = Lock()

    def _cleanup(self, key: str, now: float) -> None:
        cutoff = now - self.window_seconds
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]

    def is_allowed(self, key: str) -> bool:
        """Check if a request from this key is allowed."""
        now = time.time()
        with self._lock:
            self._cleanup(key, now)
            if len(self._requests[key]) < self.max_requests:
                self._requests[key].append(now)
                return True
            return False

    def remaining(self, key: str) -> int:
        """Get remaining requests in the current window."""
        now = time.time()
        with self._lock:
            self._cleanup(key, now)
            return max(0, self.max_requests - len(self._requests[key]))

    def reset_time(self, key: str) -> int:
        """Get the time until the oldest request expires."""
        now = time.time()
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
        return f"ip:{forwarded.split(',')[0].strip()}"
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
