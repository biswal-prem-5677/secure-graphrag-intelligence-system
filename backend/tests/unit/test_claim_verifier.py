import pytest
from app.evaluation.claim_verifier import claim_verifier
from app.schemas.schemas import EvidenceRecord, GraphData, GraphNode, RelationshipStep


def test_atomic_claim_extraction():
    answer = "PHANTOM DRAGON operates DragonScale. It targets defense firms in the US. Incident Response IR-2023-003 corroborated C2."
    claims = claim_verifier.extract_atomic_claims(answer)
    assert len(claims) >= 2


def test_verify_supported_claims():
    graph = GraphData(
        nodes=[GraphNode(id="act-001", name="PHANTOM DRAGON", label="ThreatActor")],
        edges=[],
    )
    paths = [RelationshipStep(source="PHANTOM DRAGON", relation="USES", target="DragonScale")]
    ev = [EvidenceRecord(source_id="CERT", title="CERT 2022", source_type="A", confidence=0.9, summary="S")]
    res = claim_verifier.verify_answer("PHANTOM DRAGON uses DragonScale.", graph, paths, ev)
    assert res.faithfulness_score == 1.0
    assert res.is_fully_grounded is True
