import pytest
from app.evaluation.confidence import confidence_scorer
from app.schemas.schemas import ConfidenceLevel, EvidenceRecord, GraphData, GraphNode, RelationshipStep


def test_high_confidence_scoring():
    graph = GraphData(
        nodes=[GraphNode(id="1", name="A", label="L"), GraphNode(id="2", name="B", label="L")],
        edges=[],
    )
    paths = [RelationshipStep(source="A", relation="USES", target="B")]
    ev = [EvidenceRecord(source_id="1", title="T", source_type="A", confidence=0.9, summary="S")]
    level, expl = confidence_scorer.score(graph, paths, ev)
    assert level == ConfidenceLevel.HIGH
    assert "High confidence" in expl


def test_insufficient_confidence_scoring():
    level, expl = confidence_scorer.score(GraphData(), [], [], is_insufficient_answer=True)
    assert level == ConfidenceLevel.INSUFFICIENT
    assert "Insufficient evidence" in expl
