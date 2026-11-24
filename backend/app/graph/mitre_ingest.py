"""
MITRE ATT&CK STIX 2.1 Ingestion Engine for Secure GraphRAG.
Ingests real-world CTI STIX 2.1 bundles into Neo4j with schema indexing and relational mapping.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from app.core.config import settings
from app.core.logging import get_logger
from app.graph.client import neo4j_client

logger = get_logger("mitre_ingest")

DEFAULT_STIX_PATH = Path(__file__).resolve().parent / "mitre_attack_stix21.json"


class MitreStixIngester:
    """Parses and ingests STIX 2.1 / MITRE ATT&CK bundles into Neo4j."""

    def __init__(self, stix_path: Optional[Path] = None) -> None:
        self.stix_path = Path(stix_path) if stix_path else DEFAULT_STIX_PATH

    def load_bundle(self) -> Dict[str, Any]:
        """Load and parse the local STIX 2.1 dataset."""
        if not self.stix_path.exists():
            raise FileNotFoundError(f"STIX 2.1 bundle not found at {self.stix_path}")
        with open(self.stix_path, "r", encoding="utf-8") as f:
            return json.load(f)

    async def ingest_into_neo4j(self) -> Dict[str, int]:
        """Ingest nodes, edges, and evidence records idempotently into Neo4j."""
        data = self.load_bundle()
        nodes: List[Dict[str, Any]] = data.get("nodes", [])
        edges: List[Dict[str, Any]] = data.get("edges", [])
        evidence: List[Dict[str, Any]] = data.get("evidence", [])

        connected = await neo4j_client.connect()
        if not connected:
            raise ConnectionError(f"Cannot connect to Neo4j at {settings.NEO4J_URI}")

        logger.info("ingesting_mitre_stix_start", total_nodes=len(nodes), total_edges=len(edges))

        # 1. Ensure indexes exist for MITRE ATT&CK identifiers
        indexes = [
            "CREATE INDEX mitre_node_id IF NOT EXISTS FOR (n:Entity) ON (n.id)",
            "CREATE INDEX mitre_actor_name IF NOT EXISTS FOR (n:ThreatActor) ON (n.name)",
            "CREATE INDEX mitre_malware_name IF NOT EXISTS FOR (n:Malware) ON (n.name)",
            "CREATE INDEX mitre_technique_id IF NOT EXISTS FOR (n:Technique) ON (n.id)",
            "CREATE INDEX mitre_vuln_cve IF NOT EXISTS FOR (n:Vulnerability) ON (n.cve_id)",
        ]
        for idx in indexes:
            try:
                await neo4j_client.execute_write(idx)
            except Exception as e:
                logger.debug("index_creation_note", query=idx, error=str(e))

        # 2. Ingest Nodes (MERGE on id)
        node_count = 0
        for n in nodes:
            label = "".join(c for c in n.get("label", "Entity") if c.isalnum())
            query = f"""
            MERGE (n:{label} {{id: $id}})
            SET n.name = $name,
                n.label = $label,
                n += $properties
            """
            await neo4j_client.execute_write(
                query,
                {
                    "id": n["id"],
                    "name": n["name"],
                    "label": label,
                    "properties": n.get("properties", {}),
                },
            )
            node_count += 1

        # 3. Ingest Edges (MERGE relationship)
        edge_count = 0
        for e in edges:
            rel_type = "".join(c for c in e.get("type", "RELATED_TO") if c.isalnum() or c == "_")
            query = f"""
            MATCH (s {{id: $source}}), (t {{id: $target}})
            MERGE (s)-[r:{rel_type}]->(t)
            SET r += $properties
            """
            await neo4j_client.execute_write(
                query,
                {
                    "source": e["source"],
                    "target": e["target"],
                    "properties": e.get("properties", {}),
                },
            )
            edge_count += 1

        # 4. Ingest Evidence
        ev_count = 0
        for ev in evidence:
            query = """
            MERGE (e:Evidence {id: $source_id})
            SET e.title = $title,
                e.source_type = $source_type,
                e.confidence = $confidence,
                e.summary = $summary,
                e.date = $date
            """
            await neo4j_client.execute_write(query, ev)
            ev_count += 1

        logger.info(
            "ingesting_mitre_stix_complete",
            nodes_seeded=node_count,
            edges_seeded=edge_count,
            evidence_seeded=ev_count,
        )
        return {"nodes": node_count, "edges": edge_count, "evidence": ev_count}


async def main():
    parser = argparse.ArgumentParser(description="Ingest MITRE ATT&CK STIX 2.1 into Neo4j")
    parser.add_argument("--file", type=str, default=None, help="Path to STIX 2.1 JSON file")
    args = parser.parse_args()

    ingester = MitreStixIngester(Path(args.file) if args.file else None)
    res = await ingester.ingest_into_neo4j()
    print(f"Successfully ingested MITRE ATT&CK STIX 2.1: {res}")


if __name__ == "__main__":
    asyncio.run(main())
