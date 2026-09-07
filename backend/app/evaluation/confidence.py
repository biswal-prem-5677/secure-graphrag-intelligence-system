"""
ConfidenceScorer: Computes explainable, metric-driven confidence scores (HIGH, MEDIUM, LOW, INSUFFICIENT).
"""
from __future__ import annotations

from typing import List, Tuple
from app.schemas.schemas import ConfidenceLevel, EvidenceRecord, GraphData, RelationshipStep


class ConfidenceScorer:
    """Computes explainable, metric-driven confidence scores."""

    def score(
        self,
        graph_data: GraphData,
        relationship_paths: List[RelationshipStep],
        evidence_records: List[EvidenceRecord],
        is_insufficient_answer: bool = False,
    ) -> Tuple[ConfidenceLevel, str]:
        if is_insufficient_answer or not graph_data.nodes:
            return (
                ConfidenceLevel.INSUFFICIENT,
                "Insufficient evidence: No verified graph nodes or relationship paths exist in the intelligence base.",
            )

        num_nodes = len(graph_data.nodes)
        num_paths = len(relationship_paths)
        num_sources = len(evidence_records)

        # High Confidence: >= 2 nodes, >= 1 path, >= 1 evidence record
        if num_nodes >= 2 and num_paths >= 1 and num_sources >= 1:
            return (
                ConfidenceLevel.HIGH,
                f"High confidence: Supported by {num_nodes} verified graph entities, and {num_paths} explicit relationship transitions; {num_sources} primary source(s) cited.",
            )

        # Medium Confidence: graph node exists with paths or sources
        if num_nodes >= 1 and (num_paths >= 1 or num_sources >= 1):
            return (
                ConfidenceLevel.MEDIUM,
                f"Medium confidence: Supported by {num_nodes} graph entities and {num_sources} corroborating intelligence sources, {num_paths} relationship links.",
            )

        # Low Confidence
        return (
            ConfidenceLevel.LOW,
            f"Low confidence: Entity found ({num_nodes} node), but relationship links or corroborating evidence are sparse.",
        )


confidence_scorer = ConfidenceScorer()
