"""
QueryAnalyzer: Deterministic entity extraction, multi-hop traversal planning, and intent mapping.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel
from app.core.logging import get_logger

logger = get_logger("query_analyzer")

# Canonical threat entities for deterministic resolution
CANONICAL_ENTITIES = [
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


def _build_known_entities() -> List[str]:
    """Compile canonical test entities + MITRE ATT&CK STIX 2.1 knowledge base."""
    entities: List[str] = list(CANONICAL_ENTITIES)
    seen: Set[str] = {e.lower() for e in entities}

    # Load MITRE ATT&CK STIX 2.1 graph
    mitre_path = Path(__file__).resolve().parent.parent / "graph" / "mitre_attack_stix21.json"
    if not mitre_path.exists():
        mitre_path = Path("backend/app/graph/mitre_attack_stix21.json")

    if mitre_path.exists():
        try:
            with open(mitre_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for node in data.get("nodes", []):
                    name = node.get("name")
                    if name and len(name) >= 3 and name.lower() not in seen:
                        entities.append(name)
                        seen.add(name.lower())
                    # Include aliases / short names
                    if "properties" in node and "aliases" in node["properties"]:
                        for alias in node["properties"]["aliases"]:
                            if alias and len(alias) >= 3 and alias.lower() not in seen:
                                entities.append(alias)
                                seen.add(alias.lower())
                    # Include threat actor nicknames (e.g., Lazarus from Lazarus Group)
                    if node.get("label") == "ThreatActor" and name:
                        for token in name.split():
                            if len(token) >= 4 and token.lower() not in seen and token.lower() not in ("team", "group", "actor"):
                                entities.append(token)
                                seen.add(token.lower())
        except Exception as e:
            logger.warning("failed_to_load_mitre_entities_into_analyzer", error=str(e))

    # Sort descending by length so longer multi-word phrases match before subsets
    return sorted(entities, key=lambda x: len(x), reverse=True)


KNOWN_ENTITIES = _build_known_entities()


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

        # Extract ATT&CK Technique IDs (e.g., T1059, T1059.001)
        tech_ids = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", q, re.IGNORECASE)
        for tid in tech_ids:
            entities.append(tid.upper())

        # Extract CVEs
        cves = re.findall(r"\bCVE-\d{4}-[\w-]+\b", q, re.IGNORECASE)
        for cve in cves:
            entities.append(cve.upper())

        # Extract IPs
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q)

        # Extract domains
        domains = re.findall(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b", q)
        # Filter out common punctuation mistakes
        domains = [d for d in domains if not d.endswith(".py") and not d.endswith(".json")]

        # Determine multi-hop depth
        is_multi_hop = False
        max_hops = 2
        multi_hop_triggers = [
            "connect", "infrastructure", "chain", "through", "campaign", "lead to", "via", "path",
            "employ", "utilize", "deploy", "leverage", "target", "framework", "technique", "trojan",
            "malware", "ransomware", "actor", "affiliate", "group"
        ]
        if any(trig in q.lower() for trig in multi_hop_triggers) or len(entities) >= 2:
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
