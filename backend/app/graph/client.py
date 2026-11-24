"""
Neo4j async driver wrapper with connection management, query execution, and fallback state.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Optional
from neo4j import AsyncGraphDatabase, AsyncDriver
from neo4j.exceptions import ServiceUnavailable, AuthError
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("neo4j_client")


class Neo4jClient:
    """Neo4j async driver wrapper with connection management."""

    def __init__(self) -> None:
        self.uri = settings.NEO4J_URI
        self.user = settings.NEO4J_USER
        self.password = os.environ.get("SECRET_NEO4J_PASSWORD") or settings.NEO4J_PASSWORD
        self.driver: Optional[AsyncDriver] = None
        self._connected = False
        self._lock: Optional[asyncio.Lock] = None
        self._last_connect_failure_time: float = 0.0
        self._cooldown_seconds: float = 30.0

    @property
    def is_connected(self) -> bool:
        """Return current connection status without performing network I/O."""
        return self._connected and self.driver is not None

    @property
    def lock(self) -> asyncio.Lock:
        """Lazy lock initialization to bind to active event loop."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def connect(self) -> bool:
        """Initialize the Neo4j driver with concurrency protection."""
        async with self.lock:
            return await self._connect_locked()

    async def _connect_locked(self) -> bool:
        """Internal driver initialization executed under lock."""
        self.uri = settings.NEO4J_URI
        self.user = settings.NEO4J_USER
        self.password = os.environ.get("SECRET_NEO4J_PASSWORD") or settings.NEO4J_PASSWORD

        if self.driver:
            try:
                await self.driver.close()
            except Exception:
                pass
            self.driver = None
            self._connected = False

        try:
            driver = AsyncGraphDatabase.driver(
                self.uri, auth=(self.user, self.password), max_connection_lifetime=3600
            )
            await driver.verify_connectivity()
            self.driver = driver
            self._connected = True
            logger.info("neo4j_connected", uri=self.uri)
            return True
        except AuthError as e:
            logger.error("neo4j_auth_failed", error=str(e))
            self._connected = False
            return False
        except Exception as e:
            logger.warning("neo4j_connection_failed", uri=self.uri, error=str(e))
            self._connected = False
            import time
            self._last_connect_failure_time = time.time()
            return False

    async def reconnect(self) -> bool:
        """Safely attempt to reconnect if disconnected, avoiding connection storms."""
        async with self.lock:
            if self.driver and self._connected:
                try:
                    await self.driver.verify_connectivity()
                    return True
                except Exception:
                    self._connected = False
            return await self._connect_locked()

    async def close(self) -> None:
        """Close the driver."""
        async with self.lock:
            if self.driver:
                try:
                    await self.driver.close()
                except Exception:
                    pass
                self.driver = None
                self._connected = False
                logger.info("neo4j_disconnected")

    async def is_healthy(self) -> bool:
        """Check if Neo4j is reachable. Reuses existing driver if connected; respects cooldown on failed attempts."""
        if self.driver and self._connected:
            try:
                await self.driver.verify_connectivity()
                return True
            except Exception:
                self._connected = False

        import time
        if not self._connected and (time.time() - self._last_connect_failure_time < self._cooldown_seconds):
            return False

        return await self.reconnect()

    async def execute_read(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if not self.driver or not self._connected:
            raise ServiceUnavailable("Neo4j client not connected")
        async with self.driver.session() as session:
            result = await session.run(query, parameters or {})
            records = await result.data()
            return records

    async def execute_write(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> Any:
        """Execute a write Cypher query with parameters (for seeding only)."""
        if not self.driver or not self._connected:
            raise ServiceUnavailable("Neo4j client not connected")
        async with self.driver.session() as session:
            result = await session.run(query, parameters or {})
            return await result.consume()


neo4j_client = Neo4jClient()
