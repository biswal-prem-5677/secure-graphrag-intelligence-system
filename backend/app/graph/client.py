"""
Neo4j async driver wrapper with connection management, query execution, and fallback state.
"""
from __future__ import annotations

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
        self.password = settings.NEO4J_PASSWORD
        self.driver: Optional[AsyncDriver] = None
        self._connected = False

    async def connect(self) -> bool:
        """Initialize the Neo4j driver."""
        try:
            self.driver = AsyncGraphDatabase.driver(
                self.uri, auth=(self.user, self.password), max_connection_lifetime=3600
            )
            await self.driver.verify_connectivity()
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
            return False

    async def close(self) -> None:
        """Close the driver."""
        if self.driver:
            await self.driver.close()
            self._connected = False
            logger.info("neo4j_disconnected")

    async def is_healthy(self) -> bool:
        """Check if Neo4j is reachable."""
        if not self.driver or not self._connected:
            return False
        try:
            await self.driver.verify_connectivity()
            return True
        except Exception:
            return False

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
