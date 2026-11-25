"""
GraphRetriever: Traverses Neo4j knowledge graph with parameterized multi-hop Cypher
and an indexed NetworkX in-memory fallback loaded once from the official ATT&CK v20.1 bundle.
"""
from __future__ import annotations

import difflib
import gzip
import json
import os
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx
from pydantic import BaseModel

from app.core.config import settings
from app.core.logging import get_logger
from app.graph.client import neo4j_client
from app.schemas.schemas import EvidenceRecord, GraphData, GraphEdge, GraphNode, RelationshipStep

logger = get_logger("graph_retriever")

# Canonical Threat Intelligence Test Fixture (strictly loaded in testing / smoke test runs)
TEST_FIXTURE_GRAPH_DATA = {
    "nodes": [
        {"id": "act-001", "name": "PHANTOM DRAGON", "label": "ThreatActor", "properties": {"origin": "Unknown", "status": "Active"}},
        {"id": "act-002", "name": "CRIMSON WOLF", "label": "ThreatActor", "properties": {"origin": "Eastern Europe", "status": "Active"}},
        {"id": "act-003", "name": "SHADOW VIPER", "label": "ThreatActor", "properties": {"origin": "Unknown", "status": "Dormant"}},
        {"id": "cmp-001", "name": "Operation Jade Storm", "label": "Campaign", "properties": {"year": 2023, "target_sector": "Defense"}},
        {"id": "mal-001", "name": "DragonScale", "label": "Malware", "properties": {"type": "Backdoor", "platform": "Windows"}},
        {"id": "mal-002", "name": "Cobalt Strike", "label": "Malware", "properties": {"type": "C2 Framework", "platform": "Cross-platform"}},
        {"id": "mal-003", "name": "CerberusLock", "label": "Malware", "properties": {"type": "Ransomware", "platform": "Windows"}},
        {"id": "mal-004", "name": "PhantomLoader", "label": "Malware", "properties": {"type": "Dropper", "platform": "Windows"}},
        {"id": "vuln-001", "name": "CVE-2023-38831", "label": "Vulnerability", "properties": {"severity": "High", "cve_id": "CVE-2023-38831"}},
        {"id": "vuln-002", "name": "CVE-2023-DEMO-001", "label": "Vulnerability", "properties": {"severity": "Critical", "cve_id": "CVE-2023-DEMO-001"}},
        {"id": "tgt-001", "name": "Apex Defense Corp", "label": "Target", "properties": {"industry": "Defense", "country": "United States"}},
        {"id": "tgt-002", "name": "Metro Health System", "label": "Target", "properties": {"industry": "Healthcare", "country": "United States"}},
        {"id": "ip-001", "name": "203.0.113.42", "label": "IPAddress", "properties": {"type": "C2", "address": "203.0.113.42"}},
        {"id": "ip-002", "name": "198.51.100.25", "label": "IPAddress", "properties": {"type": "Relay", "address": "198.51.100.25"}},
        {"id": "geo-001", "name": "United States", "label": "Country", "properties": {"code": "US"}},
    ],
    "edges": [
        {"source": "act-001", "target": "cmp-001", "type": "CONDUCTS", "properties": {"source_id": "CERT-2022-041", "confidence": 0.95}},
        {"source": "act-001", "target": "mal-001", "type": "USES", "properties": {"source_id": "CERT-2022-041", "confidence": 0.95}},
        {"source": "act-001", "target": "mal-002", "type": "USES", "properties": {"source_id": "CERT-2022-041", "confidence": 0.95}},
        {"source": "act-001", "target": "vuln-001", "type": "EXPLOITS", "properties": {"source_id": "CERT-2022-041", "confidence": 0.95}},
        {"source": "cmp-001", "target": "tgt-001", "type": "TARGETS", "properties": {"source_id": "IR-2023-003", "confidence": 0.90}},
        {"source": "mal-001", "target": "ip-001", "type": "COMMUNICATES_WITH", "properties": {"source_id": "IR-2023-003", "confidence": 0.90}},
        {"source": "mal-001", "target": "vuln-002", "type": "EXPLOITS", "properties": {"source_id": "IR-2023-003", "confidence": 0.90}},
        {"source": "act-002", "target": "mal-003", "type": "USES", "properties": {"source_id": "IR-2023-88", "confidence": 0.88}},
        {"source": "act-002", "target": "tgt-002", "type": "TARGETS", "properties": {"source_id": "IR-2023-88", "confidence": 0.88}},
        {"source": "act-002", "target": "tgt-001", "type": "TARGETS", "properties": {"source_id": "IR-2023-88", "confidence": 0.88}},
        {"source": "tgt-001", "target": "geo-001", "type": "LOCATED_IN", "properties": {"source_id": "IR-2023-003", "confidence": 0.95}},
        {"source": "tgt-002", "target": "geo-001", "type": "LOCATED_IN", "properties": {"source_id": "IR-2023-88", "confidence": 0.95}},
    ],
    "evidence": [
        {
            "source_id": "CERT-2022-041",
            "title": "CERT Advisory 2022-041",
            "source_type": "Advisory",
            "confidence": 0.95,
            "summary": "PHANTOM DRAGON campaigns deploy DragonScale and Cobalt Strike against defense contractors including Apex Defense Corp.",
            "date": "2022-11-14",
        },
        {
            "source_id": "IR-2023-003",
            "title": "Incident Response Report IR-2023-003",
            "source_type": "IncidentReport",
            "confidence": 0.90,
            "summary": "Operation Jade Storm intrusion analysis confirms C2 communication to 203.0.113.42 via DragonScale backdoor.",
            "date": "2023-04-18",
        },
        {
            "source_id": "IR-2023-88",
            "title": "Incident Report IR-2023-88",
            "source_type": "IncidentReport",
            "confidence": 0.88,
            "summary": "CRIMSON WOLF intrusion deployed CerberusLock ransomware across healthcare targets.",
            "date": "2023-09-02",
        },
    ],
}

# Preserve export alias for legacy test imports
OFFLINE_GRAPH_DATA = TEST_FIXTURE_GRAPH_DATA


class ScoredEntityCandidate(BaseModel):
    node: GraphNode
    score: float
    match_type: str


class RetrievalResult(BaseModel):
    graph_data: GraphData
    relationship_paths: List[RelationshipStep]
    evidence_records: List[EvidenceRecord]
    entities_found: List[str]


class GraphRetriever:
    """Safely traverses Neo4j with parameterized Cypher and an indexed NetworkX fallback."""

    def __init__(self) -> None:
        self._cached_data: Optional[Dict[str, Any]] = None
        self._nx_graph: Optional[nx.MultiDiGraph] = None
        self._evidence_by_id: Dict[str, Dict[str, Any]] = {}
        self._nodes_by_id: Dict[str, Dict[str, Any]] = {}
        self._include_fixture_state: Optional[bool] = None

    def _should_include_fixture(self) -> bool:
        return (
            getattr(settings, "ENVIRONMENT", "development") == "testing"
            or os.environ.get("INCLUDE_TEST_FIXTURE", "").lower() == "true"
        )

    def _ensure_loaded(self) -> None:
        include_fixture = self._should_include_fixture()
        if self._cached_data is not None and self._include_fixture_state == include_fixture:
            return

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        evidence: List[Dict[str, Any]] = []
        seen_node_ids: Set[str] = set()
        metadata: Dict[str, Any] = {}

        # Load compiled Official MITRE ATT&CK v20.1 graph ONCE
        gz_path = Path(__file__).resolve().parent.parent / "graph" / "attack_enterprise_v20_1.json.gz"
        if not gz_path.exists():
            gz_path = Path("backend/app/graph/attack_enterprise_v20_1.json.gz")

        if gz_path.exists():
            try:
                with gzip.open(gz_path, "rt", encoding="utf-8") as f:
                    file_data = json.load(f)
                metadata = file_data.get("metadata", {})
                for n in file_data.get("nodes", []):
                    if n["id"] not in seen_node_ids:
                        nodes.append(n)
                        seen_node_ids.add(n["id"])
                edges.extend(file_data.get("edges", []))
                evidence.extend(file_data.get("evidence", []))
            except Exception as e:
                logger.warning("failed_loading_official_attack_gz", error=str(e))

        # Load test fixture ONLY when running in testing or explicit smoke-test mode
        if include_fixture:
            for n in TEST_FIXTURE_GRAPH_DATA["nodes"]:
                if n["id"] not in seen_node_ids:
                    nodes.append(n)
                    seen_node_ids.add(n["id"])
            # Prevent duplicate fixture edges
            seen_edges = {(e["source"], e["type"], e["target"]) for e in edges}
            for e in TEST_FIXTURE_GRAPH_DATA["edges"]:
                if (e["source"], e["type"], e["target"]) not in seen_edges:
                    edges.append(e)
            evidence.extend(TEST_FIXTURE_GRAPH_DATA["evidence"])

        # Build fast O(1) indexes and NetworkX MultiDiGraph
        g = nx.MultiDiGraph()
        nodes_by_id: Dict[str, Dict[str, Any]] = {}
        for n in nodes:
            nodes_by_id[n["id"]] = n
            g.add_node(n["id"], **n)

        for e in edges:
            if e["source"] in nodes_by_id and e["target"] in nodes_by_id:
                g.add_edge(e["source"], e["target"], key=e["type"], rel_type=e["type"], properties=e.get("properties", {}))

        evidence_by_id: Dict[str, Dict[str, Any]] = {ev["source_id"]: ev for ev in evidence if "source_id" in ev}

        self._cached_data = {
            "metadata": metadata,
            "nodes": nodes,
            "edges": edges,
            "evidence": evidence,
        }
        self._nx_graph = g
        self._nodes_by_id = nodes_by_id
        self._evidence_by_id = evidence_by_id
        self._include_fixture_state = include_fixture
        logger.info(
            "graph_index_loaded",
            nodes=len(nodes),
            edges=len(edges),
            evidence=len(evidence),
            include_fixture=include_fixture,
        )

    def _get_offline_data(self) -> Dict[str, Any]:
        """Return cached graph dataset without disk I/O per query."""
        self._ensure_loaded()
        return self._cached_data  # type: ignore

    async def resolve_entities_scored(self, entity_names: List[str], limit_per_term: int = 5) -> List[ScoredEntityCandidate]:
        """Resolve entity mentions using Neo4j full-text index or fuzzy matching against aliases and ATT&CK IDs."""
        if not entity_names:
            return []

        candidates: List[ScoredEntityCandidate] = []

        # 1. Try live Neo4j Full-Text Search
        if await neo4j_client.is_healthy():
            for name in entity_names:
                try:
                    cypher_ft = """
                    CALL db.index.fulltext.queryNodes("entityFulltext", $q) YIELD node, score
                    RETURN node.id AS id, node.name AS name, labels(node)[0] AS label, properties(node) AS props, score
                    ORDER BY score DESC LIMIT $limit
                    """
                    logger.info("executing_cypher_fulltext_resolve", term=name)
                    records = await neo4j_client.execute_read(cypher_ft, {"q": name, "limit": limit_per_term})
                    for r in records:
                        candidates.append(
                            ScoredEntityCandidate(
                                node=GraphNode(id=r["id"], name=r["name"], label=r["label"], properties=r.get("props", {})),
                                score=float(r.get("score", 1.0)),
                                match_type="neo4j_fulltext",
                            )
                        )
                except Exception:
                    # Graceful fallback to parameterized Cypher case-insensitive match if fulltext index unavailable
                    try:
                        cypher_fallback = """
                        MATCH (n)
                        WHERE toLower(n.name) CONTAINS toLower($name)
                           OR toLower(coalesce(n.attack_id, '')) = toLower($name)
                           OR toLower(coalesce(n.aliases_str, '')) CONTAINS toLower($name)
                        RETURN n.id AS id, n.name AS name, labels(n)[0] AS label, properties(n) AS props
                        LIMIT $limit
                        """
                        records = await neo4j_client.execute_read(cypher_fallback, {"name": name, "limit": limit_per_term})
                        for r in records:
                            candidates.append(
                                ScoredEntityCandidate(
                                    node=GraphNode(id=r["id"], name=r["name"], label=r["label"], properties=r.get("props", {})),
                                    score=0.90,
                                    match_type="neo4j_property",
                                )
                            )
                    except Exception as e2:
                        logger.warning("neo4j_entity_resolution_failed", name=name, error=str(e2))

        # 2. Indexed NetworkX / Fuzzy Matching Fallback
        if not candidates:
            self._ensure_loaded()
            for name in entity_names:
                q_low = name.strip().lower()
                if not q_low:
                    continue
                scored_local: List[ScoredEntityCandidate] = []
                for nid, n in self._nodes_by_id.items():
                    n_name_l = n["name"].lower()
                    n_id_l = nid.lower()
                    aliases = [a.lower() for a in n.get("properties", {}).get("aliases", [])]

                    if q_low == n_id_l or q_low == n_name_l:
                        scored_local.append(
                            ScoredEntityCandidate(
                                node=GraphNode(id=n["id"], name=n["name"], label=n["label"], properties=n.get("properties", {})),
                                score=1.0,
                                match_type="exact",
                            )
                        )
                    elif q_low in aliases:
                        scored_local.append(
                            ScoredEntityCandidate(
                                node=GraphNode(id=n["id"], name=n["name"], label=n["label"], properties=n.get("properties", {})),
                                score=0.95,
                                match_type="alias",
                            )
                        )
                    elif len(q_low) >= 4 and (q_low in n_name_l or any(q_low in a for a in aliases)):
                        scored_local.append(
                            ScoredEntityCandidate(
                                node=GraphNode(id=n["id"], name=n["name"], label=n["label"], properties=n.get("properties", {})),
                                score=0.85,
                                match_type="substring",
                            )
                        )
                    elif len(q_low) >= 5:
                        sim = difflib.SequenceMatcher(None, q_low, n_name_l).ratio()
                        if sim >= 0.78:
                            scored_local.append(
                                ScoredEntityCandidate(
                                    node=GraphNode(id=n["id"], name=n["name"], label=n["label"], properties=n.get("properties", {})),
                                    score=round(sim, 3),
                                    match_type="fuzzy",
                                )
                            )

                scored_local.sort(key=lambda c: c.score, reverse=True)
                candidates.extend(scored_local[:limit_per_term])

        # Deduplicate keeping highest score per node ID
        best_by_id: Dict[str, ScoredEntityCandidate] = {}
        for cand in candidates:
            existing = best_by_id.get(cand.node.id)
            if not existing or cand.score > existing.score:
                best_by_id[cand.node.id] = cand
        return sorted(best_by_id.values(), key=lambda c: c.score, reverse=True)

    async def resolve_entities(self, entity_names: List[str]) -> List[GraphNode]:
        """Resolve entity names to canonical nodes in the graph."""
        scored = await self.resolve_entities_scored(entity_names)
        return [c.node for c in scored]

    async def retrieve_subgraph(
        self,
        entity_names: List[str],
        max_depth: int = 2,
        intended_rels: Optional[List[str]] = None,
        max_paths: int = 50,
        hub_degree_cap: int = 15,
    ) -> RetrievalResult:
        """
        Execute bounded, typed, directed multi-hop graph traversal from resolved seed entities.
        Uses live Neo4j Cypher variable-length path queries when connected, otherwise executes
        directed BFS over the indexed NetworkX MultiDiGraph with hub-degree capping.
        """
        matched_nodes = await self.resolve_entities(entity_names)
        if not matched_nodes:
            return RetrievalResult(
                graph_data=GraphData(),
                relationship_paths=[],
                evidence_records=[],
                entities_found=[],
            )

        depth = max(1, min(4, int(max_depth)))
        seed_ids = [n.id for n in matched_nodes]
        allowed_rels = [r.upper() for r in intended_rels] if intended_rels else None

        sub_nodes: Dict[str, GraphNode] = {n.id: n for n in matched_nodes}
        sub_edges: List[GraphEdge] = []
        seen_edge_keys: Set[Tuple[str, str, str]] = set()
        paths: List[RelationshipStep] = []
        seen_paths: Set[Tuple[str, str, str]] = set()
        evidence_ids_referenced: Set[str] = {f"MITRE-{n.id}" for n in matched_nodes}

        # 1. Live Neo4j Parameterized Cypher Multi-Hop Traversal
        neo4j_used = False
        if await neo4j_client.is_healthy():
            try:
                # Variable-length bound must be literal integer in Cypher; strictly bounded 1..4
                cypher_path = f"""
                MATCH (seed) WHERE seed.id IN $seed_ids
                MATCH p = (seed)-[rels*1..{depth}]->(target)
                WHERE ($allowed_rels IS NULL OR ALL(r IN rels WHERE type(r) IN $allowed_rels))
                WITH p, length(p) AS hop_len,
                     reduce(minC = 1.0, r IN rels | CASE WHEN coalesce(r.confidence, 0.9) < minC THEN coalesce(r.confidence, 0.9) ELSE minC END) AS path_conf
                ORDER BY hop_len ASC, path_conf DESC
                LIMIT $max_paths
                RETURN [n IN nodes(p) | {{id: n.id, name: n.name, label: labels(n)[0], properties: properties(n)}}] AS path_nodes,
                       [r IN relationships(p) | {{source: startNode(r).id, target: endNode(r).id, type: type(r), properties: properties(r)}}] AS path_rels
                """
                logger.info(
                    "executing_cypher_traversal",
                    seed_ids=seed_ids,
                    max_depth=depth,
                    intended_rels=allowed_rels,
                    max_paths=max_paths,
                    cypher=cypher_path.strip(),
                )
                records = await neo4j_client.execute_read(
                    cypher_path,
                    {"seed_ids": seed_ids, "allowed_rels": allowed_rels, "max_paths": max_paths},
                )
                for rec in records:
                    for pn in rec.get("path_nodes", []):
                        if pn["id"] not in sub_nodes:
                            sub_nodes[pn["id"]] = GraphNode(
                                id=pn["id"],
                                name=pn["name"],
                                label=pn.get("label", "Entity"),
                                properties=pn.get("properties", {}),
                            )
                        evidence_ids_referenced.add(f"MITRE-{pn['id']}")
                    for pr in rec.get("path_rels", []):
                        ek = (pr["source"], pr["type"], pr["target"])
                        if ek not in seen_edge_keys:
                            seen_edge_keys.add(ek)
                            props = pr.get("properties", {})
                            sub_edges.append(GraphEdge(source=pr["source"], target=pr["target"], type=pr["type"], properties=props))
                            if "source_id" in props:
                                evidence_ids_referenced.add(props["source_id"])
                        src_name = sub_nodes[pr["source"]].name if pr["source"] in sub_nodes else pr["source"]
                        tgt_name = sub_nodes[pr["target"]].name if pr["target"] in sub_nodes else pr["target"]
                        pk = (src_name, pr["type"], tgt_name)
                        if pk not in seen_paths:
                            seen_paths.add(pk)
                            paths.append(RelationshipStep(source=src_name, relation=pr["type"], target=tgt_name))
                neo4j_used = True
            except Exception as e:
                logger.warning("neo4j_cypher_traversal_failed_using_fallback", error=str(e))

        # 2. Indexed NetworkX MultiDiGraph Directed BFS Fallback
        if not neo4j_used:
            self._ensure_loaded()
            g = self._nx_graph
            if g is not None:
                queue = deque([(sid, 0) for sid in seed_ids if sid in g])
                visited_depths: Dict[str, int] = {sid: 0 for sid in seed_ids if sid in g}

                while queue and len(sub_edges) < max_paths:
                    curr_id, curr_d = queue.popleft()
                    if curr_d >= depth:
                        continue

                    # Collect outgoing directed edges; include incoming only at hop 0 if outgoing degree is 0
                    # (e.g. querying a Vulnerability/Technique/Mitigation to see what actors/malware target/use it)
                    candidate_edges = list(g.out_edges(curr_id, keys=True, data=True))
                    if curr_d == 0 and len(candidate_edges) == 0:
                        candidate_edges = [(u, v, k, d) for u, v, k, d in g.in_edges(curr_id, keys=True, data=True)]

                    # Sort by edge confidence descending and enforce hub-degree cap
                    candidate_edges.sort(
                        key=lambda x: float(x[3].get("properties", {}).get("confidence", 0.9)),
                        reverse=True,
                    )

                    neighbors_added = 0
                    for u, v, rel_type, edata in candidate_edges:
                        if neighbors_added >= hub_degree_cap or len(sub_edges) >= max_paths:
                            break
                        if allowed_rels and rel_type not in allowed_rels and curr_d == 0 and len(candidate_edges) > 3:
                            continue

                        ek = (u, rel_type, v)
                        if ek not in seen_edge_keys:
                            seen_edge_keys.add(ek)
                            props = edata.get("properties", {})
                            sub_edges.append(GraphEdge(source=u, target=v, type=rel_type, properties=props))
                            if "source_id" in props:
                                evidence_ids_referenced.add(props["source_id"])

                            for nid in (u, v):
                                if nid not in sub_nodes and nid in self._nodes_by_id:
                                    ndata = self._nodes_by_id[nid]
                                    sub_nodes[nid] = GraphNode(
                                        id=ndata["id"],
                                        name=ndata["name"],
                                        label=ndata["label"],
                                        properties=ndata.get("properties", {}),
                                    )
                                    evidence_ids_referenced.add(f"MITRE-{nid}")

                            src_name = sub_nodes[u].name if u in sub_nodes else u
                            tgt_name = sub_nodes[v].name if v in sub_nodes else v
                            pk = (src_name, rel_type, tgt_name)
                            if pk not in seen_paths:
                                seen_paths.add(pk)
                                paths.append(RelationshipStep(source=src_name, relation=rel_type, target=tgt_name))
                            neighbors_added += 1

                        next_node = v if u == curr_id else u
                        if next_node not in visited_depths or visited_depths[next_node] > curr_d + 1:
                            visited_depths[next_node] = curr_d + 1
                            queue.append((next_node, curr_d + 1))

        # 3. Provenance-Linked Evidence Retrieval (linked directly to edge source_ids & node ATT&CK citations)
        self._ensure_loaded()
        evidence_records: List[EvidenceRecord] = []
        seen_ev_ids: Set[str] = set()
        for src_id in evidence_ids_referenced:
            ev = self._evidence_by_id.get(src_id)
            if ev and src_id not in seen_ev_ids:
                seen_ev_ids.add(src_id)
                evidence_records.append(
                    EvidenceRecord(
                        source_id=ev["source_id"],
                        title=ev["title"],
                        source_type=ev["source_type"],
                        confidence=ev["confidence"],
                        summary=ev["summary"],
                        date=ev.get("date"),
                    )
                )
        # Keep top 15 highest-confidence provenance citations to fit token budgets
        evidence_records.sort(key=lambda e: e.confidence, reverse=True)
        evidence_records = evidence_records[:15]

        return RetrievalResult(
            graph_data=GraphData(nodes=list(sub_nodes.values()), edges=sub_edges),
            relationship_paths=paths,
            evidence_records=evidence_records,
            entities_found=[n.name for n in matched_nodes],
        )


graph_retriever = GraphRetriever()
