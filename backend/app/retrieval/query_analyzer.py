"""
QueryAnalyzer: Entity extraction, fuzzy/alias resolution, multi-hop traversal planning, and intent mapping.
"""
from __future__ import annotations

import difflib
import gzip
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("query_analyzer")

CANONICAL_TEST_ENTITIES = [
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

    def __init__(self) -> None:
        self._vocab_loaded: bool = False
        self._fixture_mode: Optional[bool] = None
        self._sorted_entities: List[str] = []
        self._lower_to_canonical: Dict[str, str] = {}
        self._compiled_regexes: List[re.Pattern] = []

    def _should_include_fixture(self) -> bool:
        return (
            getattr(settings, "ENVIRONMENT", "development") == "testing"
            or os.environ.get("INCLUDE_TEST_FIXTURE", "").lower() == "true"
        )

    def _ensure_vocab_loaded(self) -> None:
        include_fixture = self._should_include_fixture()
        if self._vocab_loaded and self._fixture_mode == include_fixture:
            return

        entities: List[str] = []
        seen: Set[str] = set()

        def _add(term: str, canonical: Optional[str] = None) -> None:
            t = term.strip()
            if len(t) < 3:
                return
            tl = t.lower()
            generic_single_nouns = {
                "and", "the", "for", "with", "use", "uses", "team", "group", "actor", "system", "data",
                "tool", "tools", "botnet", "server", "email", "file", "files", "script", "account",
                "accounts", "network", "service", "services", "domain", "channel", "software", "browser",
                "process", "proxy", "remote", "share", "registry", "at", "net", "reg", "sc",
            }
            if " " not in tl and tl in generic_single_nouns:
                return
            if tl not in seen:
                seen.add(tl)
                entities.append(t)
                self._lower_to_canonical[tl] = canonical or t

        if include_fixture:
            for e in CANONICAL_TEST_ENTITIES:
                _add(e, e)

        gz_path = Path(__file__).resolve().parent.parent / "graph" / "attack_enterprise_v20_1.json.gz"
        if not gz_path.exists():
            gz_path = Path("backend/app/graph/attack_enterprise_v20_1.json.gz")

        if gz_path.exists():
            try:
                with gzip.open(gz_path, "rt", encoding="utf-8") as f:
                    data = json.load(f)
                for node in data.get("nodes", []):
                    name = node.get("name", "").strip()
                    if name:
                        _add(name, name)
                    for alias in node.get("properties", {}).get("aliases", []):
                        if alias:
                            _add(alias, name)
            except Exception as e:
                logger.warning("query_analyzer_vocab_load_error", error=str(e))

        self._sorted_entities = sorted(entities, key=len, reverse=True)
        # Compile chunked alternation patterns for O(1)-like fast multi-pattern matching
        self._compiled_regexes = []
        chunk_size = 300
        for i in range(0, len(self._sorted_entities), chunk_size):
            chunk = self._sorted_entities[i : i + chunk_size]
            escaped = [re.escape(ent) for ent in chunk]
            pat = re.compile(r"(?i)\b(?:" + "|".join(escaped) + r")\b")
            self._compiled_regexes.append(pat)

        self._vocab_loaded = True
        self._fixture_mode = include_fixture

    def rule_based_analysis(self, query: str) -> QueryAnalysisResult:
        """Fast deterministic + fuzzy entity extraction and multi-hop intent mapping."""
        self._ensure_vocab_loaded()
        q = query.strip()
        entities: List[str] = []

        # 1. Exact/Alias match via precompiled alternation regexes
        for pat in self._compiled_regexes:
            for match in pat.finditer(q):
                matched_text = match.group(0)
                canonical = self._lower_to_canonical.get(matched_text.lower(), matched_text)
                entities.append(canonical)

        # 2. Extract ATT&CK External IDs (Techniques T1xxx, Groups G0xxx, Software S0xxx, Mitigations M1xxx)
        attack_ids = re.findall(r"\b[TGSM]\d{4}(?:\.\d{3})?\b", q, re.IGNORECASE)
        for aid in attack_ids:
            entities.append(aid.upper())

        # 3. Extract CVEs, IPs, Domains
        cves = re.findall(r"\bCVE-\d{4}-[\w-]+\b", q, re.IGNORECASE)
        for cve in cves:
            entities.append(cve.upper())

        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q)

        domains = re.findall(r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b", q)
        domains = [d for d in domains if not d.endswith(".py") and not d.endswith(".json")]

        # 4. Fuzzy candidate fallback if exact matches returned nothing
        if not entities and not ips and not cves:
            # Extract capitalized noun phrases or technical words >= 5 chars as fuzzy candidates
            phrase_candidates = re.findall(r"\b(?:[A-Z][a-zA-Z0-9_-]{2,}(?:\s+[A-Z][a-zA-Z0-9_-]{2,})*)\b", q)
            vocab_keys = list(self._lower_to_canonical.keys())
            for cand in phrase_candidates:
                if cand.lower() in ("what", "which", "where", "when", "does", "tell", "about", "how"):
                    continue
                close = difflib.get_close_matches(cand.lower(), vocab_keys, n=1, cutoff=0.80)
                if close:
                    entities.append(self._lower_to_canonical[close[0]])

        # 5. Multi-hop depth determination
        is_multi_hop = False
        max_hops = 2
        multi_hop_triggers = [
            "connect", "infrastructure", "chain", "through", "campaign", "lead to", "via", "path",
            "employ", "utilize", "deploy", "leverage", "target", "framework", "technique", "trojan",
            "malware", "ransomware", "actor", "affiliate", "group", "mitigat",
        ]
        if any(trig in q.lower() for trig in multi_hop_triggers) or len(entities) >= 2:
            is_multi_hop = True
            max_hops = 3

        # 6. Intended relationship type mapping
        rel_map = {
            "target": ["TARGETS", "USES"],
            "malware": ["USES"],
            "tool": ["USES"],
            "use": ["USES"],
            "utilize": ["USES"],
            "deploy": ["USES"],
            "employ": ["USES"],
            "exploit": ["USES", "EXPLOITS"],
            "mitigat": ["MITIGATES"],
            "prevent": ["MITIGATES"],
            "block": ["MITIGATES"],
            "conduct": ["CONDUCTS", "ATTRIBUTED_TO"],
            "attribut": ["ATTRIBUTED_TO"],
            "subtechnique": ["SUBTECHNIQUE_OF"],
            "located": ["LOCATED_IN"],
            "c2": ["COMMUNICATES_WITH", "USES_INFRASTRUCTURE", "USES"],
            "infrastructure": ["USES_INFRASTRUCTURE", "COMMUNICATES_WITH", "USES"],
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
