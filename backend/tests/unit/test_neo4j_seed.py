"""
Unit tests for Neo4j database seeding mechanism.
Verifies idempotency, error handling on connection failure, and write execution.
"""
import pytest
from unittest.mock import AsyncMock, patch
from app.graph.seed import seed_database


@pytest.mark.asyncio
async def test_seed_database_offline_raises_connection_error():
    """Verify seed_database raises ConnectionError when Neo4j is unreachable."""
    with patch("app.graph.seed.neo4j_client.connect", new_callable=AsyncMock) as mock_connect:
        mock_connect.return_value = False
        with pytest.raises(ConnectionError, match="Failed to connect to Neo4j"):
            await seed_database()


@pytest.mark.asyncio
async def test_seed_database_idempotent_execution():
    """Verify seed_database executes MERGE queries across nodes, edges, and evidence."""
    with patch("app.graph.seed.neo4j_client.connect", new_callable=AsyncMock) as mock_connect, \
         patch("app.graph.seed.neo4j_client.execute_write", new_callable=AsyncMock) as mock_write, \
         patch("app.graph.seed.neo4j_client.execute_read", new_callable=AsyncMock) as mock_read, \
         patch("app.graph.seed.neo4j_client.close", new_callable=AsyncMock) as mock_close:

        mock_connect.return_value = True
        mock_read.side_effect = [
            [{"count": 126}],  # total nodes
            [{"count": 99}],  # total rels
        ]

        result = await seed_database()

        assert result["status"] == "success"
        assert result["nodes_seeded"] >= 15
        assert result["edges_seeded"] >= 12
        assert result["evidence_seeded"] >= 3
        assert result["total_nodes"] == 126
        assert result["total_relationships"] == 99

        # Verify execute_write was called with Cypher MERGE queries
        assert mock_write.call_count > 0
        written_queries = [call.args[0] for call in mock_write.call_args_list]
        assert any("MERGE" in q for q in written_queries)
        assert any("CREATE INDEX" in q for q in written_queries)
        assert mock_close.await_count == 1
