"""
Unit tests for Phase 4 upgrades:
- ClaimVerifier v2: Structured triples, direction reversal, negation flips, unknown entity default rejection, temporal/CVE grounding
- ConfidenceScorer: Continuous Platt-calibrated monotonicity
"""
from app.evaluation.claim_verifier import StructuredClaim, claim_verifier
from app.evaluation.confidence import confidence_scorer
from app.schemas.schemas import ConfidenceLevel, EvidenceRecord, GraphData, GraphEdge, GraphNode, RelationshipStep


def _sample_context():
    gd = GraphData(
        nodes=[
            GraphNode(id="G0007", name="APT28", label="ThreatActor"),
            GraphNode(id="S0154", name="Cobalt Strike", label="Malware"),
            GraphNode(id="T1055", name="Process Injection", label="Technique"),
        ],
        edges=[
            GraphEdge(source="G0007", target="S0154", type="USES", properties={"source_id": "MITRE-REL-G0007-S0154"}),
            GraphEdge(source="S0154", target="T1055", type="USES", properties={"source_id": "MITRE-REL-S0154-T1055"}),
        ],
    )
    paths = [
        RelationshipStep(source="APT28", relation="USES", target="Cobalt Strike"),
        RelationshipStep(source="Cobalt Strike", relation="USES", target="Process Injection"),
    ]
    evs = [
        EvidenceRecord(
            source_id="MITRE-REL-G0007-S0154",
            title="MITRE ATT&CK APT28 -> Cobalt Strike",
            source_type="MITRE STIX Relationship",
            confidence=0.95,
            summary="APT28 has used Cobalt Strike since 2019 in defense intrusions.",
            date="2024-05-01",
        )
    ]
    return gd, paths, evs


def test_structured_claim_verification():
    gd, paths, evs = _sample_context()
    idx = claim_verifier._build_grounding_index(gd, paths, evs)

    valid_sc = StructuredClaim(subject="APT28", relation="USES", object="Cobalt Strike", evidence_id="MITRE-REL-G0007-S0154")
    ok, _ = claim_verifier.verify_structured_claim(valid_sc, idx)
    assert ok is True

    rev_sc = StructuredClaim(subject="Cobalt Strike", relation="USES", object="APT28")
    ok_rev, reason = claim_verifier.verify_structured_claim(rev_sc, idx)
    assert ok_rev is False
    assert "Direction reversal" in reason

    neg_sc = StructuredClaim(subject="APT28", relation="USES", object="Cobalt Strike", negated=True)
    ok_neg, reason_neg = claim_verifier.verify_structured_claim(neg_sc, idx)
    assert ok_neg is False
    assert "Negation contradiction" in reason_neg


def test_free_text_direction_negation_temporal_and_unknown():
    gd, paths, evs = _sample_context()

    # Valid claim
    res_ok = claim_verifier.verify_answer("APT28 uses Cobalt Strike according to MITRE-REL-G0007-S0154.", gd, paths, evs)
    assert res_ok.is_fully_grounded is True

    # Direction reversal
    res_dir = claim_verifier.verify_answer("Cobalt Strike uses APT28 in operations.", gd, paths, evs)
    assert res_dir.is_fully_grounded is False

    # Relation swap
    res_rel = claim_verifier.verify_answer("APT28 mitigates Cobalt Strike.", gd, paths, evs)
    assert res_rel.is_fully_grounded is False

    # Negation contradiction
    res_neg = claim_verifier.verify_answer("APT28 did not use Cobalt Strike.", gd, paths, evs)
    assert res_neg.is_fully_grounded is False

    # Invented future year / CVE
    res_yr = claim_verifier.verify_answer("APT28 uses Cobalt Strike in 2035.", gd, paths, evs)
    assert res_yr.is_fully_grounded is False

    # Unknown entity rejected by default
    res_unk = claim_verifier.verify_answer("APT28 deployed VoidCrypter.", gd, paths, evs)
    assert res_unk.is_fully_grounded is False


def test_platt_calibrated_confidence_monotonicity():
    gd, paths, evs = _sample_context()
    p_high, lvl_high, _ = confidence_scorer.score_continuous(gd, paths, evs, faithfulness_score=1.0)
    p_med, _, _ = confidence_scorer.score_continuous(gd, paths, evs, faithfulness_score=0.5)
    p_low, lvl_low, _ = confidence_scorer.score_continuous(gd, paths, evs, faithfulness_score=0.0)

    assert p_high > p_med > p_low
    assert lvl_high == ConfidenceLevel.HIGH
    assert lvl_low in (ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM)
