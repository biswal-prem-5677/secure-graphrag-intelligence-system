"""
Idempotent Neo4j Threat Intelligence & STIX graph database seeding mechanism.
Seeds canonical cybersecurity threat entities and relationships from OFFLINE_GRAPH_DATA.
Safe to execute multiple times (uses Cypher MERGE).
"""
from __future__ import annotations

import asyncio
import sys
from typing import Any, Dict, Tuple
from app.core.config import settings
from app.core.logging import get_logger
from app.graph.client import neo4j_client
from app.retrieval.graph_retriever import OFFLINE_GRAPH_DATA

logger = get_logger("graph_seed")


async def seed_database() -> Dict[str, Any]:
    """
    Idempotently seeds Neo4j with canonical threat intelligence entities,
    relationships, and evidence records.
    Returns dictionary with final node and relationship counts.
    """
    logger.info("neo4j_seeding_initiated", uri=settings.NEO4J_URI)

    connected = await neo4j_client.connect()
    if not connected:
        msg = f"Failed to connect to Neo4j at {settings.NEO4J_URI}. Ensure Neo4j is running."
        logger.error("neo4j_seed_connection_failed", error=msg)
        raise ConnectionError(msg)

    try:
        # 1. Create schema indexes for rapid entity lookups
        index_queries = [
            "CREATE INDEX threat_actor_name IF NOT EXISTS FOR (n:ThreatActor) ON (n.name)",
            "CREATE INDEX campaign_name IF NOT EXISTS FOR (n:Campaign) ON (n.name)",
            "CREATE INDEX malware_name IF NOT EXISTS FOR (n:Malware) ON (n.name)",
            "CREATE INDEX vulnerability_cve IF NOT EXISTS FOR (n:Vulnerability) ON (n.cve_id)",
            "CREATE INDEX ip_address IF NOT EXISTS FOR (n:IPAddress) ON (n.address)",
        ]
        for iq in index_queries:
            try:
                await neo4j_client.execute_write(iq)
            except Exception as e:
                # Some Neo4j editions or configurations may log index warnings
                logger.warning("neo4j_index_creation_warning", query=iq, error=str(e))

        # 2. Seed Nodes (Idempotent MERGE)
        nodes = OFFLINE_GRAPH_DATA.get("nodes", [])
        for node in nodes:
            label = node.get("label", "Entity")
            # Sanitize label to alphanumeric only for safety
            safe_label = "".join(c for c in label if c.isalnum())
            query = f"""
            MERGE (n:{safe_label} {{id: $id}})
            SET n.name = $name,
                n += $properties
            """
            await neo4j_client.execute_write(
                query,
                {
                    "id": node["id"],
                    "name": node["name"],
                    "properties": node.get("properties", {}),
                },
            )

        # 3. Seed Edges (Idempotent MERGE)
        edges = OFFLINE_GRAPH_DATA.get("edges", [])
        for edge in edges:
            rel_type = edge.get("type", "RELATED_TO")
            safe_type = "".join(c for c in rel_type if c.isalnum() or c == "_")
            query = f"""
            MATCH (s {{id: $source}}), (t {{id: $target}})
            MERGE (s)-[r:{safe_type}]->(t)
            SET r += $properties
            """
            await neo4j_client.execute_write(
                query,
                {
                    "source": edge["source"],
                    "target": edge["target"],
                    "properties": edge.get("properties", {}),
                },
            )

        # 4. Seed Evidence Records
        evidence_list = OFFLINE_GRAPH_DATA.get("evidence", [])
        for ev in evidence_list:
            query = """
            MERGE (e:Evidence {id: $source_id})
            SET e.title = $title,
                e.source_type = $source_type,
                e.confidence = $confidence,
                e.summary = $summary,
                e.date = $date
            """
            await neo4j_client.execute_write(query, ev)

        # 5. Verify Node & Relationship Counts
        node_res = await neo4j_client.execute_read("MATCH (n) RETURN count(n) AS count")
        rel_res = await neo4j_client.execute_read("MATCH ()-[r]->() RETURN count(r) AS count")
        node_count = node_res[0]["count"] if node_res else 0
        rel_count = rel_res[0]["count"] if rel_res else 0

        logger.info(
            "neo4j_seeding_completed",
            nodes_seeded=len(nodes),
            edges_seeded=len(edges),
            total_nodes_in_db=node_count,
            total_relationships_in_db=rel_count,
        )

        return {
            "status": "success",
            "nodes_seeded": len(nodes),
            "edges_seeded": len(edges),
            "evidence_seeded": len(evidence_list),
            "total_nodes": node_count,
            "total_relationships": rel_count,
        }

    finally:
        await neo4j_client.close()


def main() -> None:
    """CLI runner for Neo4j database seeding."""
    try:
        results = asyncio.run(seed_database())
        print("\n=======================================================")
        print("  NEO4J DATABASE SEEDING COMPLETED SUCCESSFULLY")
        print("=======================================================")
        print(f"  Nodes Seeded         : {results['nodes_seeded']}")
        print(f"  Edges Seeded         : {results['edges_seeded']}")
        print(f"  Evidence Records     : {results['evidence_seeded']}")
        print(f"  Total Nodes in DB    : {results['total_nodes']}")
        print(f"  Total Rels in DB     : {results['total_relationships']}")
        print("=======================================================\n")
    except ConnectionError as ce:
        print(f"\n[ERROR] Connection failed: {ce}", file=sys.stderr)
        print("Tip: If running locally without live Neo4j, the GraphRAG system operates in offline fallback mode.\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Seeding failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
