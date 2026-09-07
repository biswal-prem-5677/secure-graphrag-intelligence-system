"""
QueryCache: Thread-safe sliding-window TTL cache for normalized threat intel queries.
"""
from __future__ import annotations

import re
from threading import Lock
from typing import Any, Dict, Optional, Tuple
from cachetools import TTLCache
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("query_cache")


class QueryCache:
    """Thread-safe TTL query cache with normalization."""

    def __init__(self, maxsize: int = 500, ttl: int = 3600) -> None:
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)
        self._lock = Lock()
        self._hits = 0
        self._misses = 0

    def normalize_query(self, query: str) -> str:
        """Strip whitespace, lowercase, remove punctuation for consistent lookup key."""
        q = query.lower().strip()
        q = re.sub(r"[^\w\s\.\-]", "", q)
        q = re.sub(r"\s+", " ", q)
        return q

    def _make_key(self, query: str, user_id: Optional[str] = None) -> str:
        norm = self.normalize_query(query)
        return f"query:{norm}"

    def get(self, query: str, user_id: Optional[str] = None) -> Optional[Any]:
        """Lookup cached response for a query."""
        key = self._make_key(query, user_id)
        with self._lock:
            if key in self._cache:
                self._hits += 1
                logger.info("cache_hit", query=query)
                return self._cache[key]
            self._misses += 1
            return None

    def set(self, query: str, value: Any, user_id: Optional[str] = None) -> None:
        """Store response in cache."""
        key = self._make_key(query, user_id)
        with self._lock:
            self._cache[key] = value
            logger.info("cache_set", query=query)

    def get_stats(self) -> Dict[str, Any]:
        """Return cache performance statistics."""
        with self._lock:
            total = self._hits + self._misses
            ratio = (self._hits / total * 100) if total > 0 else 0.0
            return {
                "size": len(self._cache),
                "maxsize": self._cache.maxsize,
                "hits": self._hits,
                "misses": self._misses,
                "hit_ratio_percent": round(ratio, 2),
            }

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0


query_cache = QueryCache(
    maxsize=settings.CACHE_MAXSIZE, ttl=settings.CACHE_TTL_SECONDS
)
