"""
QueryAnalyzer: Deterministic entity extraction, multi-hop traversal planning, and intent mapping.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from app.core.logging import get_logger

logger = get_logger("query_analyzer")

# Known canonical threat entities for deterministic resolution
KNOWN_ENTITIES = [
    "PHANTOM DRAGON",
    "CRIMSON WOLF",
    "SHADOW VIPER",
    "Operation Jade Storm",
    "DragonScale",
    "Cobalt Strike",
    "CerberusLock",
    "PhantomLoader",
    "Apex Defense Corp",
    "Metro Health System",
    "United States",
]


class QueryAnalysisResult(BaseModel):
    query: str
    entities: List[str]
    cves: List[str]
    ip_addresses: List[str]
    domains: List[str]
    intended_relationships: List[str]
    max_hops: int = 2
    is_multi_hop: bool = False


class QueryAnalyzer:
    """Analyzes natural language queries to formulate a structured graph traversal plan."""

    def rule_based_analysis(self, query: str) -> QueryAnalysisResult:
        """Deterministic entity extraction and intent mapping."""
        q = query.strip()
        entities: List[str] = []

        # Extract known entities (case-insensitive boundary match)
        for entity in KNOWN_ENTITIES:
            pattern = r"(?i)\b" + re.escape(entity) + r"\b"
            if re.search(pattern, q):
                entities.append(entity)

        # Extract CVEs
        cves = re.findall(r"\bCVE-\d{4}-[\w-]+\b", q, re.IGNORECASE)

        # Extract IPs
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q)

        # Extract domains
        domains = re.findall(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b", q)
        # Filter out common punctuation mistakes
        domains = [d for d in domains if not d.endswith(".py") and not d.endswith(".json")]

        # Determine multi-hop depth
        is_multi_hop = False
        max_hops = 1
        multi_hop_triggers = ["connect", "infrastructure", "chain", "through", "campaign", "lead to", "via", "path"]
        if any(trig in q.lower() for trig in multi_hop_triggers):
            is_multi_hop = True
            max_hops = 3

        # Intent relationships
        rel_map = {
            "target": ["TARGETS"],
            "malware": ["USES"],
            "use": ["USES"],
            "exploit": ["EXPLOITS"],
            "conduct": ["CONDUCTS"],
            "located": ["LOCATED_IN"],
            "c2": ["COMMUNICATES_WITH", "USES_INFRASTRUCTURE"],
            "infrastructure": ["USES_INFRASTRUCTURE", "COMMUNICATES_WITH"],
        }
        rels: List[str] = []
        for term, mapped in rel_map.items():
            if term in q.lower():
                rels.extend(mapped)

        return QueryAnalysisResult(
            query=query,
            entities=list(dict.fromkeys(entities)),
            cves=cves,
            ip_addresses=ips,
            domains=domains,
            intended_relationships=list(dict.fromkeys(rels)),
            max_hops=max_hops,
            is_multi_hop=is_multi_hop,
        )

    def analyze(self, query: str) -> QueryAnalysisResult:
        return self.rule_based_analysis(query)


query_analyzer = QueryAnalyzer()
