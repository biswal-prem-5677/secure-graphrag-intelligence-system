#!/usr/bin/env python3
"""
Official MITRE ATT&CK Enterprise STIX 2.1 Ingestion Pipeline.
Downloads (with SHA-256 verification and caching) the pinned official STIX 2.1 bundle
from MITRE's attack-stix-data repository, parses canonical entities and directed relationships
with full external_references provenance, compiles a deterministic graph snapshot, and
optionally ingests directly into Neo4j with full-text & property indexes.

Usage:
    python scripts/ingest_attack.py                  # Download, verify, and compile JSON
    python scripts/ingest_attack.py --neo4j          # Also batch-ingest into live Neo4j
"""
from __future__ import annotations

import argparse
import asyncio
import gzip
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))

# Pinned MITRE ATT&CK Enterprise STIX 2.1 release
ATTACK_VERSION = "20.1"
ATTACK_MODIFIED = "2026-11-05T15:11:27.678Z"
ATTACK_URL = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"

RAW_CACHE_PATH = ROOT / "data" / "stix_cache" / f"enterprise-attack-{ATTACK_VERSION}.json"
COMPILED_OUT_PATH = ROOT / "backend" / "app" / "graph" / "attack_enterprise_v20_1.json.gz"

STIX_TYPE_TO_LABEL = {
    "intrusion-set": "ThreatActor",
    "malware": "Malware",
    "tool": "Tool",
    "attack-pattern": "Technique",
    "course-of-action": "Mitigation",
    "campaign": "Campaign",
}

ALLOWED_REL_TYPES = {"uses", "mitigates", "subtechnique-of", "attributed-to"}


def download_and_verify_bundle(force: bool = False) -> Tuple[Path, str]:
    """Download official MITRE ATT&CK STIX 2.1 bundle and compute SHA-256."""
    RAW_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not RAW_CACHE_PATH.exists() or force:
        print(f"Downloading official MITRE ATT&CK v{ATTACK_VERSION} STIX 2.1 bundle...")
        print(f"  Source: {ATTACK_URL}")
        with httpx.Client(timeout=120.0, follow_redirects=True) as client:
            resp = client.get(ATTACK_URL)
            resp.raise_for_status()
            RAW_CACHE_PATH.write_bytes(resp.content)
        print(f"  Saved to {RAW_CACHE_PATH} ({len(resp.content) / (1024*1024):.2f} MB)")

    sha256_hash = hashlib.sha256(RAW_CACHE_PATH.read_bytes()).hexdigest()
    print(f"  Verified Bundle SHA-256: {sha256_hash}")
    return RAW_CACHE_PATH, sha256_hash


def _extract_attack_ref(obj: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], List[Dict[str, str]]]:
    """Extract canonical ATT&CK ID (e.g. G0007, T1055), official URL, and external citations."""
    attack_id = None
    attack_url = None
    citations: List[Dict[str, str]] = []

    for ref in obj.get("external_references", []):
        src = ref.get("source_name", "")
        if src == "mitre-attack":
            attack_id = ref.get("external_id")
            attack_url = ref.get("url")
        elif src and ref.get("url"):
            citations.append({
                "source_name": src,
                "url": ref.get("url", ""),
                "description": ref.get("description", ""),
            })
    return attack_id, attack_url, citations


def parse_stix_bundle(bundle_path: Path, sha256_hash: str) -> Dict[str, Any]:
    """Parse STIX 2.1 JSON objects and relationships with provenance."""
    print(f"Parsing STIX 2.1 bundle from {bundle_path}...")
    raw = json.loads(bundle_path.read_text(encoding="utf-8"))
    objects = raw.get("objects", [])

    stix_id_to_canonical: Dict[str, str] = {}
    nodes: List[Dict[str, Any]] = []
    evidence_map: Dict[str, Dict[str, Any]] = {}
    seen_ids: Set[str] = set()

    # Pass 1: Extract domain entities (skip revoked & deprecated)
    for obj in objects:
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue
        stype = obj.get("type")
        if stype not in STIX_TYPE_TO_LABEL:
            continue

        stix_id = obj["id"]
        name = obj.get("name", "").strip()
        if not name:
            continue

        attack_id, attack_url, citations = _extract_attack_ref(obj)
        canonical_id = attack_id if (attack_id and attack_id not in seen_ids) else stix_id
        seen_ids.add(canonical_id)
        stix_id_to_canonical[stix_id] = canonical_id

        aliases = obj.get("aliases", []) or obj.get("x_mitre_aliases", []) or []
        aliases = [a for a in aliases if a and a.lower() != name.lower()]
        tactics = [
            kp.get("phase_name", "")
            for kp in obj.get("kill_chain_phases", [])
            if kp.get("kill_chain_name") == "mitre-attack"
        ]

        desc = (obj.get("description") or "").strip()
        # Keep concise description to avoid bloating compiled JSON while preserving substance
        short_desc = desc[:600] + ("..." if len(desc) > 600 else "")

        node_entry = {
            "id": canonical_id,
            "stix_id": stix_id,
            "attack_id": attack_id or "",
            "name": name,
            "label": STIX_TYPE_TO_LABEL[stype],
            "properties": {
                "attack_id": attack_id or "",
                "stix_id": stix_id,
                "url": attack_url or "",
                "aliases": aliases,
                "aliases_str": " ".join(aliases),
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "description": short_desc,
                "source_version": f"MITRE-ATT&CK-v{ATTACK_VERSION}",
            },
        }
        nodes.append(node_entry)

        # Store external references as primary evidence provenance
        if attack_id and attack_url:
            ev_id = f"MITRE-{attack_id}"
            evidence_map[ev_id] = {
                "source_id": ev_id,
                "title": f"MITRE ATT&CK {attack_id}: {name}",
                "source_type": "MITRE ATT&CK Official",
                "url": attack_url,
                "confidence": 0.98,
                "summary": short_desc or f"Official MITRE ATT&CK entry for {name} ({attack_id}).",
                "date": obj.get("modified", ATTACK_MODIFIED)[:10],
            }

    # Pass 2: Extract directed relationships with provenance
    edges: List[Dict[str, Any]] = []
    seen_edges: Set[Tuple[str, str, str]] = set()

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        rel_type = obj.get("relationship_type", "").lower()
        if rel_type not in ALLOWED_REL_TYPES:
            continue

        src_stix = obj.get("source_ref")
        tgt_stix = obj.get("target_ref")
        if src_stix not in stix_id_to_canonical or tgt_stix not in stix_id_to_canonical:
            continue

        src_id = stix_id_to_canonical[src_stix]
        tgt_id = stix_id_to_canonical[tgt_stix]
        rel_upper = rel_type.upper().replace("-", "_")

        edge_key = (src_id, rel_upper, tgt_id)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)

        rel_desc = (obj.get("description") or "").strip()
        _, _, rel_cites = _extract_attack_ref(obj)
        source_id = f"MITRE-REL-{src_id}-{tgt_id}"
        cite_url = rel_cites[0]["url"] if rel_cites else f"https://attack.mitre.org/"

        edges.append({
            "source": src_id,
            "target": tgt_id,
            "type": rel_upper,
            "properties": {
                "stix_id": obj.get("id", ""),
                "source_id": source_id,
                "url": cite_url,
                "confidence": 0.95,
                "description": rel_desc[:400],
            },
        })

        # Add relationship-level evidence record so edge provenance resolves cleanly
        if rel_desc:
            evidence_map[source_id] = {
                "source_id": source_id,
                "title": f"MITRE ATT&CK Relationship ({src_id} -> {rel_upper} -> {tgt_id})",
                "source_type": "MITRE STIX Relationship",
                "url": cite_url,
                "confidence": 0.95,
                "summary": rel_desc[:500],
                "date": obj.get("modified", ATTACK_MODIFIED)[:10],
            }

    compiled = {
        "metadata": {
            "source": "mitre-attack/attack-stix-data",
            "version": ATTACK_VERSION,
            "modified": ATTACK_MODIFIED,
            "sha256": sha256_hash,
            "compiled_at": datetime.now(timezone.utc).isoformat(),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "evidence_count": len(evidence_map),
        },
        "nodes": nodes,
        "edges": edges,
        "evidence": list(evidence_map.values()),
    }

    COMPILED_OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(COMPILED_OUT_PATH, "wt", encoding="utf-8") as gz_f:
        json.dump(compiled, gz_f, separators=(",", ":"))
    print(f"Compiled Official ATT&CK v{ATTACK_VERSION} Graph -> {COMPILED_OUT_PATH}")
    print(f"  Nodes: {len(nodes)} | Edges: {len(edges)} | Evidence Records: {len(evidence_map)}")
    return compiled


async def ingest_to_neo4j(compiled: Dict[str, Any]) -> None:
    """Batch-ingest official compiled ATT&CK STIX graph into Neo4j with full-text index."""
    from app.core.config import settings
    from app.graph.client import neo4j_client

    print(f"\nConnecting to Neo4j at {settings.NEO4J_URI} for batch ingestion...")
    connected = await neo4j_client.connect()
    if not connected:
        print(f"Error: Neo4j is not reachable at {settings.NEO4J_URI}. Skipping DB load.")
        return

    try:
        # 1. Schema & Full-Text Indexes
        indexes = [
            "CREATE INDEX actor_id IF NOT EXISTS FOR (n:ThreatActor) ON (n.id)",
            "CREATE INDEX malware_id IF NOT EXISTS FOR (n:Malware) ON (n.id)",
            "CREATE INDEX tool_id IF NOT EXISTS FOR (n:Tool) ON (n.id)",
            "CREATE INDEX technique_id IF NOT EXISTS FOR (n:Technique) ON (n.id)",
            "CREATE INDEX mitigation_id IF NOT EXISTS FOR (n:Mitigation) ON (n.id)",
            "CREATE INDEX campaign_id IF NOT EXISTS FOR (n:Campaign) ON (n.id)",
            (
                "CREATE FULLTEXT INDEX entityFulltext IF NOT EXISTS "
                "FOR (n:ThreatActor|Malware|Tool|Technique|Mitigation|Campaign) "
                "ON EACH [n.name, n.attack_id, n.aliases_str]"
            ),
        ]
        for idx_q in indexes:
            try:
                await neo4j_client.execute_write(idx_q)
            except Exception as e:
                print(f"  Index warning: {e}")

        # 2. Batch ingest nodes grouped by label
        nodes_by_label: Dict[str, List[Dict[str, Any]]] = {}
        for n in compiled["nodes"]:
            nodes_by_label.setdefault(n["label"], []).append(n)

        for label, batch_nodes in nodes_by_label.items():
            safe_label = "".join(c for c in label if c.isalnum())
            chunk_size = 500
            for i in range(0, len(batch_nodes), chunk_size):
                chunk = batch_nodes[i : i + chunk_size]
                cypher = f"""
                UNWIND $rows AS row
                MERGE (n:{safe_label} {{id: row.id}})
                SET n.name = row.name,
                    n.attack_id = row.attack_id,
                    n.stix_id = row.stix_id,
                    n += row.properties
                """
                await neo4j_client.execute_write(cypher, {"rows": chunk})
            print(f"  Ingested {len(batch_nodes)} :{safe_label} nodes")

        # 3. Batch ingest edges grouped by relationship type
        edges_by_type: Dict[str, List[Dict[str, Any]]] = {}
        for e in compiled["edges"]:
            edges_by_type.setdefault(e["type"], []).append(e)

        for rel_type, batch_edges in edges_by_type.items():
            safe_rel = "".join(c for c in rel_type if c.isalnum() or c == "_")
            chunk_size = 500
            for i in range(0, len(batch_edges), chunk_size):
                chunk = batch_edges[i : i + chunk_size]
                cypher = f"""
                UNWIND $rows AS row
                MATCH (s {{id: row.source}})
                MATCH (t {{id: row.target}})
                MERGE (s)-[r:{safe_rel} {{source_id: row.properties.source_id}}]->(t)
                SET r += row.properties
                """
                await neo4j_client.execute_write(cypher, {"rows": chunk})
            print(f"  Ingested {len(batch_edges)} :{safe_rel} edges")

        # 4. Verify database counts
        res_n = await neo4j_client.execute_read("MATCH (n) RETURN count(n) AS count")
        res_e = await neo4j_client.execute_read("MATCH ()-[r]->() RETURN count(r) AS count")
        print(f"Neo4j Ingestion Verified -> Total DB Nodes: {res_n[0]['count']}, Total DB Edges: {res_e[0]['count']}")
    finally:
        await neo4j_client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest Official MITRE ATT&CK Enterprise STIX 2.1")
    parser.add_argument("--force-download", action="store_true", help="Re-download bundle even if cached")
    parser.add_argument("--neo4j", action="store_true", help="Batch-ingest into live Neo4j database")
    args = parser.parse_args()

    bundle_path, sha256_hash = download_and_verify_bundle(force=args.force_download)
    compiled = parse_stix_bundle(bundle_path, sha256_hash)

    if args.neo4j:
        asyncio.run(ingest_to_neo4j(compiled))


if __name__ == "__main__":
    main()
