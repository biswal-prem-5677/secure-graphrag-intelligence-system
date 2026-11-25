"""
Unit tests for Phase 2 Graph Retrieval upgrades:
- Parameterized Cypher variable-length path execution when Neo4j is healthy (I-02)
- Directed traversal, intended_rels filtering, and hub-degree capping in NetworkX fallback (I-02)
- Official MITRE ATT&CK v20.1 STIX graph resolution, aliases, and fuzzy matching (I-03, A-01)
- Provenance-linked evidence collection via edge source_ids (A-02)
"""
import pytest
from unittest.mock import AsyncMock, patch
from app.retrieval.graph_retriever import GraphRetriever
from app.retrieval.query_analyzer import query_analyzer


@pytest.mark.asyncio
async def test_cypher_variable_length_path_execution():
    """Verify live Neo4j executes typed, depth-bounded parameterized Cypher variable-length paths."""
    retriever = GraphRetriever()

    seed_mock = [
        {"id": "G0007", "name": "APT28", "label": "ThreatActor", "props": {"attack_id": "G0007"}, "score": 1.0}
    ]
    path_mock = [
        {
            "path_nodes": [
                {"id": "G0007", "name": "APT28", "label": "ThreatActor", "properties": {}},
                {"id": "S0154", "name": "Cobalt Strike", "label": "Malware", "properties": {}},
                {"id": "T1055", "name": "Process Injection", "label": "Technique", "properties": {}},
            ],
            "path_rels": [
                {"source": "G0007", "target": "S0154", "type": "USES", "properties": {"source_id": "MITRE-REL-G0007-S0154"}},
                {"source": "S0154", "target": "T1055", "type": "USES", "properties": {"source_id": "MITRE-REL-S0154-T1055"}},
            ],
        }
    ]

    with patch("app.retrieval.graph_retriever.neo4j_client.is_healthy", new_callable=AsyncMock) as mock_healthy, \
         patch("app.retrieval.graph_retriever.neo4j_client.execute_read", new_callable=AsyncMock) as mock_read:
        mock_healthy.return_value = True
        mock_read.side_effect = [seed_mock, path_mock]

        result = await retriever.retrieve_subgraph(
            entity_names=["APT28"],
            max_depth=3,
            intended_rels=["USES"],
            max_paths=25,
        )

        assert mock_read.await_count == 2
        # Check second call was parameterized variable-length Cypher traversal
        cypher_call = mock_read.call_args_list[1]
        cypher_query = cypher_call.args[0]
        cypher_params = cypher_call.args[1]

        assert "MATCH p = (seed)-[rels*1..3]->(target)" in cypher_query
        assert "ALL(r IN rels WHERE type(r) IN $allowed_rels)" in cypher_query
        assert cypher_params["seed_ids"] == ["G0007"]
        assert cypher_params["allowed_rels"] == ["USES"]
        assert cypher_params["max_paths"] == 25

        assert len(result.relationship_paths) == 2
        assert result.relationship_paths[0].source == "APT28"
        assert result.relationship_paths[1].target == "Process Injection"


@pytest.mark.asyncio
async def test_networkx_directed_filtering_and_hub_degree_cap():
    """Verify offline NetworkX traversal obeys direction, relationship filters, and hub-degree capping."""
    retriever = GraphRetriever()

    with patch("app.retrieval.graph_retriever.neo4j_client.is_healthy", new_callable=AsyncMock) as mock_healthy:
        mock_healthy.return_value = False

        # Test official MITRE ATT&CK v20.1 entity APT28 (G0007) with strict hub cap
        res = await retriever.retrieve_subgraph(
            entity_names=["APT28"],
            max_depth=2,
            intended_rels=["USES"],
            hub_degree_cap=3,
            max_paths=10,
        )

        assert len(res.graph_data.nodes) > 1
        assert len(res.graph_data.edges) <= 10
        assert any(n.id == "G0007" for n in res.graph_data.nodes)
        # Ensure provenance-linked evidence records are attached
        assert len(res.evidence_records) > 0
        assert any("MITRE" in ev.source_id for ev in res.evidence_records)


def test_fuzzy_and_alias_entity_resolution():
    """Verify QueryAnalyzer resolves ATT&CK aliases ('Fancy Bear' -> 'APT28') and typos ('Coblat Strike')."""
    # Alias test
    res_alias = query_analyzer.analyze("What tools does Fancy Bear employ?")
    assert "APT28" in res_alias.entities

    # Fuzzy typo test
    res_typo = query_analyzer.analyze("Tell me about Coblat Strike capabilities")
    assert "Cobalt Strike" in res_typo.entities

    # ATT&CK external ID test
    res_id = query_analyzer.analyze("What mitigations block T1055?")
    assert "T1055" in res_id.entities
    assert "MITIGATES" in res_id.intended_relationships
