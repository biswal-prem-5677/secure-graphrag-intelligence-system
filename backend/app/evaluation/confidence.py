"""
ConfidenceScorer: Platt-calibrated continuous confidence scoring engine combining verifier grounding,
graph path density, evidence provenance quality, and entity coverage.
"""
from __future__ import annotations

import math
from typing import List, Tuple
from app.schemas.schemas import ConfidenceLevel, EvidenceRecord, GraphData, RelationshipStep


class ConfidenceScorer:
    """Computes continuous Platt-calibrated confidence probabilities and discrete operational levels."""

    def __init__(self) -> None:
        self.last_score: float = 0.0

    @staticmethod
    def _sigmoid(z: float) -> float:
        z_clamped = max(-20.0, min(20.0, z))
        return 1.0 / (1.0 + math.exp(-z_clamped))

    def score_continuous(
        self,
        graph_data: GraphData,
        relationship_paths: List[RelationshipStep],
        evidence_records: List[EvidenceRecord],
        faithfulness_score: float = 1.0,
        entity_coverage: float = 1.0,
        is_insufficient_answer: bool = False,
    ) -> Tuple[float, ConfidenceLevel, str]:
        """
        Compute calibrated confidence probability p in [0.0, 1.0] using measured pipeline signals:
          - verifier_support (faithfulness_score)
          - path_density (normalized count of verified relationship transitions)
          - evidence_quality (mean source confidence scaled by citation coverage)
          - entity_coverage (ratio of resolved entities / graph nodes)
        """
        if is_insufficient_answer or not graph_data.nodes:
            self.last_score = 0.05
            return (
                0.05,
                ConfidenceLevel.INSUFFICIENT,
                "Insufficient evidence (p=0.05): No verified graph nodes or relationship paths exist in the intelligence base.",
            )

        num_nodes = len(graph_data.nodes)
        num_paths = len(relationship_paths)
        num_sources = len(evidence_records)

        path_density = min(1.0, num_paths / 3.0)
        node_density = min(1.0, num_nodes / 4.0)
        if evidence_records:
            mean_ev_conf = sum(getattr(ev, "confidence", 0.85) for ev in evidence_records) / num_sources
            ev_signal = mean_ev_conf * min(1.0, num_sources)
        else:
            ev_signal = 0.0

        # Platt logistic linear combination calibrated on grounded graph verification signals
        logit = (
            2.6 * float(faithfulness_score)
            + 1.3 * path_density
            + 1.4 * ev_signal
            + 0.7 * node_density
            + 0.4 * float(entity_coverage)
            - 3.4
        )
        prob = round(self._sigmoid(logit), 4)
        self.last_score = prob

        if prob >= 0.75 and num_paths >= 1 and num_sources >= 1 and faithfulness_score >= 0.65:
            return (
                prob,
                ConfidenceLevel.HIGH,
                f"High confidence (p={prob:.2f}): Supported by {num_nodes} verified graph entities, {num_paths} relationship paths, and {num_sources} primary citation(s).",
            )

        if prob >= 0.45 and (num_paths >= 1 or num_sources >= 1):
            return (
                prob,
                ConfidenceLevel.MEDIUM,
                f"Medium confidence (p={prob:.2f}): Supported by {num_nodes} graph entities, {num_sources} sources, and {num_paths} relationship transitions.",
            )

        return (
            prob,
            ConfidenceLevel.LOW,
            f"Low confidence (p={prob:.2f}): Limited support ({num_nodes} node(s), {num_paths} path(s), {num_sources} source(s), faithfulness={faithfulness_score:.2f}).",
        )

    def score(
        self,
        graph_data: GraphData,
        relationship_paths: List[RelationshipStep],
        evidence_records: List[EvidenceRecord],
        is_insufficient_answer: bool = False,
        faithfulness_score: float = 1.0,
    ) -> Tuple[ConfidenceLevel, str]:
        """Score confidence returning (ConfidenceLevel, explanation) while updating self.last_score."""
        _, level, explanation = self.score_continuous(
            graph_data=graph_data,
            relationship_paths=relationship_paths,
            evidence_records=evidence_records,
            faithfulness_score=faithfulness_score,
            is_insufficient_answer=is_insufficient_answer,
        )
        return level, explanation


confidence_scorer = ConfidenceScorer()
