"""
ContextBuilder: Formats graph nodes, paths, and evidence records into prompt context with strict trust boundaries.
"""
from __future__ import annotations

from typing import List
from app.schemas.schemas import EvidenceRecord, GraphData, RelationshipStep
from app.security.validation import sanitize_graph_content


class ContextBuilder:
    """Constructs prompt context with strict trust boundaries and explicit markdown formatting."""

    def build_context(
        self,
        graph_data: GraphData,
        relationship_paths: List[RelationshipStep],
        evidence_records: List[EvidenceRecord],
        max_token_budget: int = 1500,
    ) -> str:
        if not graph_data.nodes and not relationship_paths:
            return "NO RELEVANT KNOWLEDGE GRAPH SUBGRAPH FOUND."

        sections: List[str] = []

        # Section 1: Discovered Entities
        entity_lines = ["### DISCOVERED ENTITIES IN KNOWLEDGE BASE:"]
        for node in graph_data.nodes:
            clean_name = sanitize_graph_content(node.name)
            entity_lines.append(f"- **{clean_name}** [{node.label}] `(ID: {node.id})`")
        sections.append("\n".join(entity_lines))

        # Section 2: Verified Relationship Paths
        if relationship_paths:
            path_lines = ["\n### VERIFIED RELATIONSHIP PATHS:"]
            for step in relationship_paths:
                clean_src = sanitize_graph_content(step.source)
                clean_rel = sanitize_graph_content(step.relation)
                clean_tgt = sanitize_graph_content(step.target)
                path_lines.append(f"- ({clean_src}) --[{clean_rel}]--> ({clean_tgt})")
            sections.append("\n".join(path_lines))

        # Section 3: Primary Evidence & Reports
        if evidence_records:
            evidence_lines = ["\n### CORROBORATING EVIDENCE & REPORTS:"]
            for ev in evidence_records:
                clean_title = sanitize_graph_content(ev.title)
                clean_summary = sanitize_graph_content(ev.summary)
                evidence_lines.append(
                    f"- **[{ev.source_id}]** `{clean_title}` (Confidence: {ev.confidence:.2f}) -> {clean_summary}"
                )
            sections.append("\n".join(evidence_lines))

        full_context = "\n".join(sections)

        # Context Budget Enforcement (~4 chars per token)
        max_chars = max_token_budget * 4
        if len(full_context) > max_chars:
            full_context = full_context[:max_chars] + "\n... [Context truncated to fit token budget]"

        return full_context


context_builder = ContextBuilder()
