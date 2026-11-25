#!/usr/bin/env python3
"""
Programmatic Multi-Hop Benchmark Generator (Non-Circular Evaluation Suite).
Traverses the compiled Official MITRE ATT&CK Enterprise v20.1 NetworkX graph directly
to synthesize 220 multi-hop queries (2-hop, 3-hop, set-intersection, and unanswerable probes)
where gold answer entities are mathematically derived from graph paths and NEVER leaked in the question.

Outputs frozen dev/test splits:
    - evaluation/datasets/attack_v20_1_dev.jsonl  (80 tasks)
    - evaluation/datasets/attack_v20_1_test.jsonl (140 tasks)
"""
from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))

# Ensure test fixtures are EXCLUDED when generating official ATT&CK benchmark
os.environ["ENVIRONMENT"] = "development"
os.environ["INCLUDE_TEST_FIXTURE"] = "false"

from app.retrieval.graph_retriever import graph_retriever


def generate_benchmark(seed: int = 42) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rng = random.Random(seed)
    graph_retriever._ensure_loaded()
    g = graph_retriever._nx_graph
    nodes = graph_retriever._nodes_by_id
    assert g is not None

    actors = [nid for nid, n in nodes.items() if n["label"] == "ThreatActor"]
    rng.shuffle(actors)

    tasks: List[Dict[str, Any]] = []
    seen_queries: Set[str] = set()

    # ---------------------------------------------------------
    # 1. 2-Hop Paths: Actor -> USES -> Software -> USES -> Technique (70 tasks)
    # ---------------------------------------------------------
    two_hop_count = 0
    for aid in actors:
        if two_hop_count >= 70:
            break
        actor_name = nodes[aid]["name"]
        # Find software/tools used by this actor
        sw_nodes = [
            v for _, v, k, _ in g.out_edges(aid, keys=True, data=True)
            if k == "USES" and nodes.get(v, {}).get("label") in ("Malware", "Tool")
        ]
        if not sw_nodes:
            continue

        # Target techniques reachable at hop 2 through the actor's software
        hop2_techs: Set[str] = set()
        hop1_sw_names: Set[str] = set()
        for sw in sw_nodes:
            hop1_sw_names.add(nodes[sw]["name"])
            for _, t, k, _ in g.out_edges(sw, keys=True, data=True):
                if k == "USES" and nodes.get(t, {}).get("label") == "Technique":
                    hop2_techs.add(t)

        if len(hop2_techs) < 2:
            continue

        # Pick canonical entity IDs and names for shared exact matcher
        gold_ids = sorted(list(hop2_techs))[:8]
        gold_names = [nodes[tid]["name"] for tid in gold_ids]

        q = f"Which MITRE ATT&CK techniques are executed by malware or tools deployed by {actor_name} ({aid})?"
        if q in seen_queries:
            continue
        seen_queries.add(q)

        tasks.append({
            "id": f"mh2-{two_hop_count + 1:03d}",
            "query": q,
            "seed_entities": [aid, actor_name],
            "gold_entity_ids": gold_ids,
            "gold_entity_names": gold_names,
            "hop_count": 2,
            "category": "two_hop_actor_sw_tech",
        })
        two_hop_count += 1

    # ---------------------------------------------------------
    # 2. 3-Hop Paths: Actor -> Software -> Technique <- MITIGATES <- Mitigation (70 tasks)
    # ---------------------------------------------------------
    three_hop_count = 0
    # Precompute Technique <- MITIGATES <- Mitigation reverse map
    tech_to_mits: Dict[str, Set[str]] = {}
    for u, v, k, _ in g.edges(keys=True, data=True):
        if k == "MITIGATES" and nodes.get(u, {}).get("label") == "Mitigation" and nodes.get(v, {}).get("label") == "Technique":
            tech_to_mits.setdefault(v, set()).add(u)

    for aid in actors:
        if three_hop_count >= 70:
            break
        actor_name = nodes[aid]["name"]
        sw_nodes = [
            v for _, v, k, _ in g.out_edges(aid, keys=True, data=True)
            if k == "USES" and nodes.get(v, {}).get("label") in ("Malware", "Tool")
        ]
        if not sw_nodes:
            continue

        # Pick the primary malware/tool used by actor that has mapped techniques + mitigations
        for sw in sw_nodes:
            sw_name = nodes[sw]["name"]
            techs = [
                t for _, t, k, _ in g.out_edges(sw, keys=True, data=True)
                if k == "USES" and t in tech_to_mits
            ]
            if not techs:
                continue
            mits: Set[str] = set()
            for t in techs:
                mits.update(tech_to_mits[t])
            if len(mits) < 2:
                continue

            gold_ids = sorted(list(mits))[:8]
            gold_names = [nodes[mid]["name"] for mid in gold_ids]
            q = f"What MITRE ATT&CK mitigations counter techniques utilized by {sw_name} ({sw}) when deployed by {actor_name}?"
            if q in seen_queries:
                continue
            seen_queries.add(q)

            tasks.append({
                "id": f"mh3-{three_hop_count + 1:03d}",
                "query": q,
                "seed_entities": [aid, actor_name, sw, sw_name],
                "gold_entity_ids": gold_ids,
                "gold_entity_names": gold_names,
                "hop_count": 3,
                "category": "three_hop_actor_sw_tech_mit",
            })
            three_hop_count += 1
            break

    # ---------------------------------------------------------
    # 3. Set-Intersection Tasks: Shared Techniques between Actor A & Actor B (40 tasks)
    # ---------------------------------------------------------
    actor_techs: Dict[str, Set[str]] = {}
    for aid in actors:
        ts = {
            v for _, v, k, _ in g.out_edges(aid, keys=True, data=True)
            if k == "USES" and nodes.get(v, {}).get("label") == "Technique"
        }
        if len(ts) >= 3:
            actor_techs[aid] = ts

    eligible_actors = list(actor_techs.keys())
    rng.shuffle(eligible_actors)
    inter_count = 0
    for i in range(len(eligible_actors)):
        if inter_count >= 40:
            break
        for j in range(i + 1, len(eligible_actors)):
            if inter_count >= 40:
                break
            a1, a2 = eligible_actors[i], eligible_actors[j]
            shared = actor_techs[a1] & actor_techs[a2]
            if len(shared) >= 2:
                n1, n2 = nodes[a1]["name"], nodes[a2]["name"]
                gold_ids = sorted(list(shared))[:8]
                gold_names = [nodes[tid]["name"] for tid in gold_ids]
                q = f"Which ATT&CK techniques are utilized in common by both {n1} ({a1}) and {n2} ({a2})?"
                if q in seen_queries:
                    continue
                seen_queries.add(q)

                tasks.append({
                    "id": f"int-{inter_count + 1:03d}",
                    "query": q,
                    "seed_entities": [a1, n1, a2, n2],
                    "gold_entity_ids": gold_ids,
                    "gold_entity_names": gold_names,
                    "hop_count": 2,
                    "category": "set_intersection",
                })
                inter_count += 1
                break

    # ---------------------------------------------------------
    # 4. Unanswerable / Out-of-Distribution Refusal Probes (40 tasks)
    # ---------------------------------------------------------
    fictional_syndicates = [
        ("Obsidian Hydra", "G9001"), ("Solaris Lynx", "G9002"), ("Quantum Viper", "G9003"),
        ("Aether Phantom", "G9004"), ("Cobalt Mirage", "G9005"), ("Vortex Chimera", "G9006"),
        ("Nebula Wolf", "G9007"), ("Astral Jackal", "G9008"), ("Crimson Kraken", "G9009"),
        ("Titan Mantis", "G9010"), ("Zephyr Falcon", "G9011"), ("Krypton Basilisk", "G9012"),
        ("Nova Scorpion", "G9013"), ("Helios Wyvern", "G9014"), ("Boreal Sphinx", "G9015"),
        ("Zenith Griffin", "G9016"), ("Apex Gargoyle", "G9017"), ("Omega Centaur", "G9018"),
        ("Pyro Leviathan", "G9019"), ("Vega Behemoth", "G9020"),
    ]
    fictional_tools = [
        "HyperionLoader", "StarlightRAT", "VoidCrypter", "AegisStealer", "ChronosWiper",
        "NetherBeacon", "FluxBackdoor", "PrismKeylogger", "ShadowRootkit", "ZeroBotnetX",
        "EclipseImplant", "PhotonExploitKit", "RiftRansom", "MirageDropper", "NebulaShell",
        "QuantumSpyware", "PulseInjector", "OrionTunnel", "ValkyrieC2", "KestrelMiner",
    ]
    for idx in range(20):
        syn, gid = fictional_syndicates[idx]
        q = f"What malware and ATT&CK techniques are attributed to {syn} ({gid})?"
        tasks.append({
            "id": f"ref-{idx + 1:03d}",
            "query": q,
            "seed_entities": [],
            "gold_entity_ids": [],
            "gold_entity_names": [],
            "hop_count": 0,
            "category": "unanswerable_refusal",
        })
    for idx in range(20):
        tool = fictional_tools[idx]
        q = f"Which threat actor uses {tool} and which critical CVE does it exploit?"
        tasks.append({
            "id": f"ref-{idx + 21:03d}",
            "query": q,
            "seed_entities": [],
            "gold_entity_ids": [],
            "gold_entity_names": [],
            "hop_count": 0,
            "category": "unanswerable_refusal",
        })

    # Shuffle deterministically and stratify split (80 dev / 140 test)
    rng.shuffle(tasks)
    dev_set = tasks[:80]
    test_set = tasks[80:]

    ds_dir = ROOT / "evaluation" / "datasets"
    ds_dir.mkdir(parents=True, exist_ok=True)
    with open(ds_dir / "attack_v20_1_dev.jsonl", "w", encoding="utf-8") as f:
        for t in dev_set:
            f.write(json.dumps(t) + "\n")
    with open(ds_dir / "attack_v20_1_test.jsonl", "w", encoding="utf-8") as f:
        for t in test_set:
            f.write(json.dumps(t) + "\n")

    print(f"Generated {len(tasks)} programmatic MITRE ATT&CK v20.1 multi-hop tasks:")
    print(f"  2-hop: {two_hop_count} | 3-hop: {three_hop_count} | Set-Intersection: {inter_count} | Refusal: 40")
    print(f"  Saved Dev ({len(dev_set)})  -> {ds_dir / 'attack_v20_1_dev.jsonl'}")
    print(f"  Saved Test ({len(test_set)}) -> {ds_dir / 'attack_v20_1_test.jsonl'}")
    return dev_set, test_set


if __name__ == "__main__":
    generate_benchmark()
