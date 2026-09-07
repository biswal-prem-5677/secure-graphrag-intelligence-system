"""
Deterministic Mock LLM Provider for offline testing, CI/CD, and zero-cost evaluation.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from app.llm.provider import BaseLLMProvider, LLMResponse


class MockLLMProvider(BaseLLMProvider):
    """Deterministic, grounded mock LLM provider matching test fixtures and threat intel patterns."""

    async def generate_grounded_answer(
        self, query: str, graph_context: str, **kwargs: Any
    ) -> LLMResponse:
        q_lower = query.lower()

        # Check for empty context or insufficient evidence
        if not graph_context.strip() or "NO RELEVANT KNOWLEDGE GRAPH SUBGRAPH FOUND" in graph_context:
            return LLMResponse(
                answer="Insufficient evidence in the knowledge base to establish this relationship.",
                confidence="INSUFFICIENT",
                confidence_explanation="No verified graph entities or relationships found in the threat graph.",
                cited_sources=[],
            )

        # PHANTOM DRAGON + malware
        if "phantom dragon" in q_lower and ("malware" in q_lower or "cve" in q_lower or "use" in q_lower):
            return LLMResponse(
                answer="Based on verified threat intelligence records: PHANTOM DRAGON uses DragonScale for intrusions, as documented in CERT Advisory 2022-041. Direct USES relationships verified across multiple nodes with CERT advisory backing.",
                confidence="HIGH",
                confidence_explanation="Direct USES relationships verified across multiple nodes with CERT advisory backing.",
                cited_sources=["CERT Advisory 2022-041", "Incident Response IR-2023-003"],
            )

        # PHANTOM DRAGON + infrastructure
        if "phantom dragon" in q_lower and ("infra" in q_lower or "ip" in q_lower or "connect" in q_lower):
            return LLMResponse(
                answer="Based on verified threat intelligence records: PHANTOM DRAGON conducts Operation Jade Storm and utilizes DragonScale backdoor, which communicates with C2 IP address 203.0.113.42.",
                confidence="HIGH",
                confidence_explanation="Direct CONDUCTS, TARGETS, and USES edges confirmed in graph.",
                cited_sources=["CERT Advisory 2022-041", "IR-2023-003"],
            )

        # CRIMSON WOLF + targets / financial
        if "crimson wolf" in q_lower:
            return LLMResponse(
                answer="Based on verified threat intelligence records: CRIMSON WOLF targeted Apex Defense Corp and financial institutions, corroborated by Incident Response IR-2023-003 and dark web threat intelligence.",
                confidence="HIGH",
                confidence_explanation="Direct TARGETS and LOCATED_IN relationships verified in graph.",
                cited_sources=["IR-2023-003", "CERT Advisory 2022-041"],
            )

        # DragonScale / CVE
        if "dragonscale" in q_lower:
            return LLMResponse(
                answer="Based on verified threat intelligence records: DragonScale is a custom backdoor used by PHANTOM DRAGON. Direct attributes and relationships verified across threat actor nodes.",
                confidence="HIGH",
                confidence_explanation="Direct attributes and relationships verified across threat actor nodes.",
                cited_sources=["CERT Advisory 2022-041"],
            )

        # IP 203.0.113.42
        if "203.0.113.42" in q_lower:
            return LLMResponse(
                answer="Based on verified threat intelligence records: 203.0.113.42 is a verified command and control infrastructure node linked to DragonScale malware.",
                confidence="HIGH",
                confidence_explanation="Direct USES_INFRASTRUCTURE edge verified in threat graph.",
                cited_sources=["IR-2023-003"],
            )

        # General grounded fallback from context
        entities = re.findall(r"-\s+\*\*([^*]+)\*\*", graph_context)
        entity_str = ", ".join(entities[:3]) if entities else "threat entities"
        return LLMResponse(
            answer=f"Based on verified threat intelligence records: Analysis of {entity_str} shows confirmed relationships within the threat knowledge graph.",
            confidence="MEDIUM",
            confidence_explanation="Corroborated by available intelligence reports in knowledge graph.",
            cited_sources=["CERT Advisory 2022-041"],
        )
