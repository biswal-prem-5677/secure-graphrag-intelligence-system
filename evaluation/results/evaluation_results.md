# Secure GraphRAG vs. Vector-RAG Benchmark Evaluation Report

**Execution Timestamp**: 2026-11-24T06:20:55.855697+00:00  
**Evaluation Set**: `evaluation/datasets/mitre_multihop_100.jsonl` (105 multi-hop tasks)  
**Knowledge Graph Base**: 125 nodes, 99 edges, 15 CTI evidence records (MITRE ATT&CK STIX 2.1).

## Executive Summary

| Evaluation Metric | Secure GraphRAG | Plain Vector-RAG Baseline | Delta / Advantage |
| :--- | :---: | :---: | :---: |
| **Multi-Hop Entity Recall** | **67.3%** | 56.5% | **+10.8%** |
| **Task Completion Rate** | **99.0%** | 39.0% | **+60.0%** |
| **Mean Faithfulness Score** | **0.89** | 0.53 | **+35.7%** |
| **Hallucination Rate** | **11.4%** | 47.1% | **-35.7%** |
| **Latency P50** | 21.6 ms | 3.4 ms | — |
| **Latency P95** | 160.7 ms | 23.4 ms | — |

## Key Insights

1. **Why Plain Vector-RAG Fails on Multi-Hop Queries**:
   - Plain vector similarity retrieval searches for semantic proximity to the initial question. When answering 3-hop questions (e.g. *ThreatActor -> Malware -> ATT&CK Technique -> Mitigation*), the target mitigation chunk shares almost no keyword overlap with the threat actor query.
   - Vector-RAG retrieves chunks about the actor, but completely drops the 2nd and 3rd hop entities, resulting in **56.5% recall** and forcing the generator to hallucinate intermediate connections.
2. **Graph Topology Traversal Superiority**:
   - Secure GraphRAG traverses explicitly indexed Cypher relationships across the STIX 2.1 graph, discovering exact 2-hop to 4-hop pathways and citations, achieving **67.3% multi-hop recall**.
3. **Anti-Hallucination Claim Verifier**:
   - By eliminating heuristic blacklists and validating entity presence and relational path connectivity, GraphRAG suppresses ungrounded assertions, reducing hallucination rates to **11.4%**.
