"""
Comprehensive tests for Neo4jClient lifecycle, credential resolution, health probes,
controlled reconnect, concurrency safety, and GraphRAG live vs offline fallback.
"""
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi.testclient import TestClient
from app.core.config import Settings
from app.graph.client import Neo4jClient, neo4j_client
from app.main import app
from app.retrieval.graph_retriever import GraphRetriever


@pytest.fixture
def client_instance():
    """Create a fresh isolated Neo4jClient instance for testing."""
    return Neo4jClient()


@pytest.mark.asyncio
async def test_neo4j_client_connect_and_close_lifecycle(client_instance):
    """Verify connect initializes driver and close terminates it cleanly."""
    mock_driver = AsyncMock()
    mock_driver.verify_connectivity = AsyncMock()
    mock_driver.close = AsyncMock()

    with patch("app.graph.client.AsyncGraphDatabase.driver", return_value=mock_driver) as mock_factory:
        connected = await client_instance.connect()
        assert connected is True
        assert client_instance._connected is True
        assert client_instance.driver is mock_driver
        mock_factory.assert_called_once()
        mock_driver.verify_connectivity.assert_awaited_once()

        # Close
        await client_instance.close()
        assert client_instance._connected is False
        assert client_instance.driver is None
        mock_driver.close.assert_awaited_once()


def test_neo4j_password_resolution_from_secret_env():
    """Verify SECRET_NEO4J_PASSWORD is resolved into NEO4J_PASSWORD without exposure."""
    with patch.dict(os.environ, {"SECRET_NEO4J_PASSWORD": "ProductionTestSecret123!"}, clear=False):
        settings = Settings()
        assert settings.NEO4J_PASSWORD == "ProductionTestSecret123!"

        test_client = Neo4jClient()
        assert test_client.password == "ProductionTestSecret123!"
        # Verify str/repr of client does not leak raw password
        assert "ProductionTestSecret123!" not in str(test_client)


@pytest.mark.asyncio
async def test_is_healthy_after_successful_connect_reuses_driver(client_instance):
    """Verify is_healthy() reuses existing driver and does not re-instantiate."""
    mock_driver = AsyncMock()
    mock_driver.verify_connectivity = AsyncMock()

    with patch("app.graph.client.AsyncGraphDatabase.driver", return_value=mock_driver) as mock_factory:
        await client_instance.connect()
        assert mock_factory.call_count == 1

        # Check health multiple times
        h1 = await client_instance.is_healthy()
        h2 = await client_instance.is_healthy()

        assert h1 is True
        assert h2 is True
        # Driver factory was called only once (reused)
        assert mock_factory.call_count == 1
        assert mock_driver.verify_connectivity.await_count == 3  # 1 on connect + 2 on health checks


@pytest.mark.asyncio
async def test_is_healthy_when_connectivity_fails(client_instance):
    """Verify is_healthy() returns False when connectivity check fails."""
    mock_driver = AsyncMock()
    mock_driver.verify_connectivity = AsyncMock(side_effect=Exception("Connection refused"))

    with patch("app.graph.client.AsyncGraphDatabase.driver", return_value=mock_driver):
        # connect will fail verify_connectivity
        connected = await client_instance.connect()
        assert connected is False
        assert client_instance._connected is False

        # is_healthy should also return False
        healthy = await client_instance.is_healthy()
        assert healthy is False


@pytest.mark.asyncio
async def test_controlled_reconnect_replaces_broken_driver(client_instance):
    """Verify reconnect cleanly closes old broken driver before creating a new one."""
    broken_driver = AsyncMock()
    broken_driver.verify_connectivity = AsyncMock(side_effect=Exception("Broken pipe"))
    broken_driver.close = AsyncMock()

    fresh_driver = AsyncMock()
    fresh_driver.verify_connectivity = AsyncMock()
    fresh_driver.close = AsyncMock()

    # Start with broken driver
    client_instance.driver = broken_driver
    client_instance._connected = True

    # Next driver call will create fresh_driver
    with patch("app.graph.client.AsyncGraphDatabase.driver", return_value=fresh_driver) as mock_factory:
        healthy = await client_instance.is_healthy()

        assert healthy is True
        assert client_instance._connected is True
        assert client_instance.driver is fresh_driver
        broken_driver.close.assert_awaited_once()
        mock_factory.assert_called_once()


@pytest.mark.asyncio
async def test_concurrent_health_calls_prevent_driver_storms(client_instance):
    """Verify concurrent is_healthy / reconnect calls do not create multiple drivers."""
    mock_driver = AsyncMock()
    mock_driver.verify_connectivity = AsyncMock()

    call_counter = 0

    def slow_driver_factory(*args, **kwargs):
        nonlocal call_counter
        call_counter += 1
        return mock_driver

    with patch("app.graph.client.AsyncGraphDatabase.driver", side_effect=slow_driver_factory):
        # Fire 15 concurrent health checks simultaneously while disconnected
        results = await asyncio.gather(*[client_instance.is_healthy() for _ in range(15)])

        assert all(r is True for r in results)
        # Exactly one driver was created despite 15 concurrent callers
        assert call_counter == 1


def test_readiness_probe_returns_200_when_neo4j_healthy():
    """Integration test: /ready returns HTTP 200 and connected when Neo4j is healthy."""
    test_http = TestClient(app)
    with patch.object(neo4j_client, "is_healthy", new_callable=AsyncMock) as mock_health, \
         patch("app.api.health._check_postgres", return_value=(True, "connected")):
        mock_health.return_value = True

        resp = test_http.get("/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert data["neo4j"] == "connected"
        assert data["postgres"] == "connected"


def test_readiness_probe_returns_503_when_neo4j_unavailable():
    """Integration test: /ready returns HTTP 503 and degraded when Neo4j is unavailable."""
    test_http = TestClient(app)
    with patch.object(neo4j_client, "is_healthy", new_callable=AsyncMock) as mock_health, \
         patch("app.api.health._check_postgres", return_value=(True, "connected")):
        mock_health.return_value = False

        resp = test_http.get("/ready")
        assert resp.status_code == 503
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["neo4j"] == "disconnected"


@pytest.mark.asyncio
async def test_graphrag_uses_live_neo4j_when_healthy():
    """Verify GraphRetriever queries live Neo4j when healthy."""
    retriever = GraphRetriever()
    mock_records = [
        {"id": "threat-actor--live1", "name": "PHANTOM DRAGON", "label": "ThreatActor", "props": {"origin": "APT"}}
    ]

    with patch.object(neo4j_client, "is_healthy", new_callable=AsyncMock) as mock_healthy, \
         patch.object(neo4j_client, "execute_read", new_callable=AsyncMock) as mock_read:
        mock_healthy.return_value = True
        mock_read.return_value = mock_records

        nodes = await retriever.resolve_entities(["PHANTOM DRAGON"])

        assert len(nodes) == 1
        assert nodes[0].id == "threat-actor--live1"
        assert nodes[0].name == "PHANTOM DRAGON"
        mock_read.assert_awaited_once()


@pytest.mark.asyncio
async def test_graphrag_preserves_offline_fallback_when_neo4j_unavailable():
    """Verify GraphRetriever falls back to offline dictionary when Neo4j is disconnected."""
    retriever = GraphRetriever()

    with patch.object(neo4j_client, "is_healthy", new_callable=AsyncMock) as mock_healthy, \
         patch.object(neo4j_client, "execute_read", new_callable=AsyncMock) as mock_read:
        mock_healthy.return_value = False

        nodes = await retriever.resolve_entities(["PHANTOM DRAGON"])

        # Should find node from OFFLINE_GRAPH_DATA
        assert len(nodes) >= 1
        assert any("PHANTOM DRAGON" in n.name for n in nodes)
        # execute_read was never called because Neo4j was not healthy
        mock_read.assert_not_called()
