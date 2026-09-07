import pytest
from app.evaluation.claim_verifier import claim_verifier
from app.schemas.schemas import EvidenceRecord, GraphData, GraphNode, RelationshipStep


def test_faithfulness_fully_grounded_answer():
    """Verify 100% supported claims achieve a 1.0 faithfulness score."""
    graph = GraphData(
        nodes=[
            GraphNode(id="act-001", name="PHANTOM DRAGON", label="ThreatActor"),
            GraphNode(id="mal-001", name="DragonScale", label="Malware"),
        ],
        edges=[],
    )
    paths = [RelationshipStep(source="PHANTOM DRAGON", relation="USES", target="DragonScale")]
    ev = [
        EvidenceRecord(
            source_id="advisory",
            title="CERT Advisory 2022-041",
            source_type="Advisory",
            confidence=0.95,
            summary="Documented intrusion",
        )
    ]
    res = claim_verifier.verify_answer(
        "PHANTOM DRAGON uses DragonScale for intrusions, as documented in CERT Advisory 2022-041.",
        graph,
        paths,
        ev,
    )
    assert res.faithfulness_score == 1.0
    assert len(res.unsupported_claims) == 0


def test_faithfulness_penalized_by_unsupported_claims():
    """Verify unsupported claim reduces faithfulness score."""
    graph = GraphData(
        nodes=[GraphNode(id="act-001", name="PHANTOM DRAGON", label="ThreatActor")],
        edges=[],
    )
    paths = []
    ev = []
    res = claim_verifier.verify_answer(
        "PHANTOM DRAGON is an active group. They deployed fictional_alien_botnet in 2029.",
        graph,
        paths,
        ev,
    )
    assert res.faithfulness_score < 1.0
    assert len(res.unsupported_claims) >= 1
