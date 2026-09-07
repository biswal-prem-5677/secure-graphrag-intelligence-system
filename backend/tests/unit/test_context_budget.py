import pytest
from app.retrieval.context_builder import context_builder
from app.schemas.schemas import EvidenceRecord, GraphData, GraphNode, RelationshipStep


def test_context_budget_enforcement():
    nodes = [GraphNode(id=f"node-{i}", name=f"Node {i}", label="Entity") for i in range(100)]
    graph = GraphData(nodes=nodes, edges=[])
    paths = [RelationshipStep(source=f"Node {i}", relation="CONNECTS", target=f"Node {i+1}") for i in range(50)]
    evidence = [
        EvidenceRecord(
            source_id=f"EV-{i}",
            title=f"Report {i}",
            source_type="Advisory",
            confidence=0.9,
            summary="Extensive threat intelligence description text " * 10,
        )
        for i in range(20)
    ]

    # Enforce tight budget of 200 tokens (~800 chars)
    ctx = context_builder.build_context(graph, paths, evidence, max_token_budget=200)
    assert len(ctx) <= 1000
    assert "... [Context truncated to fit token budget]" in ctx
