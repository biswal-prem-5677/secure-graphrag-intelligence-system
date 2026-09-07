import sys
from pathlib import Path
_proj = Path(__file__).resolve().parents[3]
if str(_proj) not in sys.path:
    sys.path.insert(0, str(_proj))

import pytest
from app.evaluation.claim_verifier import claim_verifier
from app.schemas.schemas import GraphData, GraphNode
from evaluation.metrics.generation_metrics import evaluate_groundedness


def test_hallucination_detection_prohibited_claims():
    """Verify prohibited hallucination tokens are accurately flagged."""
    graph = GraphData(
        nodes=[GraphNode(id="act-001", name="PHANTOM DRAGON", label="ThreatActor")],
        edges=[],
    )
    answer = "ThreatActor PHANTOM DRAGON deployed Stuxnet to compromise centrifuges."
    res = claim_verifier.verify_answer(answer, graph, [], [])
    assert res.hallucination_rate > 0.0
    assert "stuxnet" in res.unsupported_claims[0].lower() or "centrifuges" in res.unsupported_claims[0].lower()


def test_correct_refusal_grounding():
    """Verify standard refusal answer has 0% hallucination and 100% refusal accuracy."""
    graph = GraphData()
    answer = "Insufficient evidence in the knowledge base to establish this relationship."
    res = claim_verifier.verify_answer(answer, graph, [], [])
    assert res.hallucination_rate == 0.0
    assert res.faithfulness_score == 1.0

    g_eval = evaluate_groundedness(answer, [], is_refusal_expected=True)
    assert g_eval["hallucination_rate"] == 0.0
    assert g_eval["refusal_correct"] is True
