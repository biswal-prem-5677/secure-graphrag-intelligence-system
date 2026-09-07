"""
GraphRetriever: Traverses Neo4j knowledge graph with offline in-memory fallback.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from app.core.config import settings
from app.core.logging import get_logger
from app.graph.client import neo4j_client
from app.schemas.schemas import EvidenceRecord, GraphData, GraphEdge, GraphNode, RelationshipStep

logger = get_logger("graph_retriever")

# Canonical Threat Intelligence Graph Dataset for testing & offline mode
OFFLINE_GRAPH_DATA = {
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
        {"source": "act-001", "target": "cmp-001", "type": "CONDUCTS", "properties": {}},
        {"source": "act-001", "target": "mal-001", "type": "USES", "properties": {}},
        {"source": "act-001", "target": "mal-002", "type": "USES", "properties": {}},
        {"source": "act-001", "target": "vuln-001", "type": "EXPLOITS", "properties": {}},
        {"source": "cmp-001", "target": "tgt-001", "type": "TARGETS", "properties": {}},
        {"source": "mal-001", "target": "ip-001", "type": "COMMUNICATES_WITH", "properties": {}},
        {"source": "mal-001", "target": "vuln-002", "type": "EXPLOITS", "properties": {}},
        {"source": "act-002", "target": "mal-003", "type": "USES", "properties": {}},
        {"source": "act-002", "target": "tgt-002", "type": "TARGETS", "properties": {}},
        {"source": "act-002", "target": "tgt-001", "type": "TARGETS", "properties": {}},
        {"source": "tgt-001", "target": "geo-001", "type": "LOCATED_IN", "properties": {}},
        {"source": "tgt-002", "target": "geo-001", "type": "LOCATED_IN", "properties": {}},
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
    ]
}


class RetrievalResult(BaseModel):
    graph_data: GraphData
    relationship_paths: List[RelationshipStep]
    evidence_records: List[EvidenceRecord]
    entities_found: List[str]


class GraphRetriever:
    """Safely traverses Neo4j with bounded depth, entity resolution, and evidence collection."""

    def _get_offline_data(self) -> Dict[str, Any]:
        data_file = Path("threat_intel_data.json")
        if data_file.exists():
            try:
                with open(data_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return OFFLINE_GRAPH_DATA

    async def resolve_entities(self, entity_names: List[str]) -> List[GraphNode]:
        """Resolve entity names to nodes in the graph (with offline fallback)."""
        nodes: List[GraphNode] = []
        if not entity_names:
            return nodes

        # Try live Neo4j
        if await neo4j_client.is_healthy():
            for name in entity_names:
                try:
                    records = await neo4j_client.execute_read(
                        "MATCH (n) WHERE toLower(n.name) CONTAINS toLower($name) RETURN n.id AS id, n.name AS name, labels(n)[0] AS label, properties(n) AS props LIMIT 5",
                        {"name": name},
                    )
                    for r in records:
                        nodes.append(GraphNode(id=r["id"], name=r["name"], label=r["label"], properties=r["props"]))
                except Exception as e:
                    logger.warning("neo4j_entity_resolution_failed", name=name, error=str(e))

        # Fallback to offline store if nothing found or offline
        if not nodes:
            data = self._get_offline_data()
            for name in entity_names:
                for n in data["nodes"]:
                    if name.lower() in n["name"].lower() or n["id"].lower() == name.lower():
                        nodes.append(
                            GraphNode(id=n["id"], name=n["name"], label=n["label"], properties=n.get("properties", {}))
                        )

        # Deduplicate
        seen = set()
        deduped = []
        for n in nodes:
            if n.id not in seen:
                seen.add(n.id)
                deduped.append(n)
        return deduped

    async def retrieve_subgraph(
        self,
        entity_names: List[str],
        max_depth: int = 2,
        intended_rels: Optional[List[str]] = None,
    ) -> RetrievalResult:
        matched_nodes = await self.resolve_entities(entity_names)
        if not matched_nodes:
            return RetrievalResult(
                graph_data=GraphData(),
                relationship_paths=[],
                evidence_records=[],
                entities_found=[],
            )

        matched_ids = {n.id for n in matched_nodes}
        data = self._get_offline_data()

        # Build subgraphs
        sub_nodes: Dict[str, GraphNode] = {n.id: n for n in matched_nodes}
        sub_edges: List[GraphEdge] = []
        paths: List[RelationshipStep] = []

        # Find connected edges up to max_depth
        frontier = set(matched_ids)
        for _ in range(max_depth):
            next_frontier = set()
            for edge in data["edges"]:
                s, t, rel_type = edge["source"], edge["target"], edge["type"]
                if s in frontier or t in frontier:
                    # Filter by intended_rels if specified
                    if intended_rels and rel_type not in intended_rels and len(sub_edges) > 5:
                        continue
                    edge_obj = GraphEdge(source=s, target=t, type=rel_type, properties=edge.get("properties", {}))
                    if edge_obj not in sub_edges:
                        sub_edges.append(edge_obj)
                        # Add target/source node
                        for n in data["nodes"]:
                            if n["id"] in (s, t) and n["id"] not in sub_nodes:
                                sub_nodes[n["id"]] = GraphNode(
                                    id=n["id"], name=n["name"], label=n["label"], properties=n.get("properties", {})
                                )
                        next_frontier.add(s)
                        next_frontier.add(t)

                        # Add relationship path step
                        src_name = sub_nodes.get(s, GraphNode(id=s, name=s, label="Node")).name
                        tgt_name = sub_nodes.get(t, GraphNode(id=t, name=t, label="Node")).name
                        paths.append(RelationshipStep(source=src_name, relation=rel_type, target=tgt_name))
            frontier = next_frontier

        # Gather evidence
        evidence_records: List[EvidenceRecord] = []
        for ev in data.get("evidence", []):
            # Include relevant evidence
            for name in entity_names:
                if name.lower() in ev["summary"].lower() or name.lower() in ev["title"].lower():
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
                    break

        return RetrievalResult(
            graph_data=GraphData(nodes=list(sub_nodes.values()), edges=sub_edges),
            relationship_paths=paths,
            evidence_records=evidence_records,
            entities_found=[n.name for n in matched_nodes],
        )


graph_retriever = GraphRetriever()
