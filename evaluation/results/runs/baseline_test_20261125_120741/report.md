# Empirical Multi-Hop Comparative Evaluation Report

**Timestamp**: 2026-11-25T12:07:41.779224+00:00 | **Commit**: `f66503f`  
**Dataset**: `evaluation/datasets/attack_v20_1_test.jsonl` (140 programmatic held-out tasks, `sha256:3c713a8a43816407`)  
**Knowledge Graph**: Official MITRE ATT&CK® Enterprise v20.1 (1827 nodes, 20957 edges)

## 1. Head-to-Head Summary (Shared Exact Canonical Matcher & Empirical ClaimVerifier)

| Canonical Metric | Secure GraphRAG | Plain BM25 Chunk RAG | Dense LSA Vector-RAG |
| :--- | :---: | :---: | :---: |
| **Retrieval Recall@K (95% CI)** | **68.7%** [62.7–74.6%] | 8.5% [5.1–12.3%] | 2.3% [1.2–3.6%] |
| **Task Completion Rate** | **56.4%** | 8.5% | 0.9% |
| **Generation Faithfulness (Answered)** | 0.80 | 1.00 | 1.00 |
| **Hallucination Rate (Answered)** | 20.5% | 0.3% | 0.1% |
| **Refusal F1 (Ungrounded Probes)** | **0.93** | 0.00 | 0.00 |
| **Latency P50** | 134.2 ms | 175.7 ms | 9.9 ms |
| **Latency P95** | 262.6 ms | 356.5 ms | 20.6 ms |

## 2. Per-Category / Per-Hop Retrieval Recall Breakdown

| Task Category | Secure GraphRAG | Plain BM25 Chunk RAG | Dense LSA Vector-RAG |
| :--- | :---: | :---: | :---: |
| **2-Hop (`Actor -> Software -> Technique`)** | **63.0%** | 3.7% | 3.0% |
| **3-Hop (`Actor -> SW -> Tech <- Mitigation`)** | **60.8%** | 0.0% | 0.0% |
| **Set Intersection (`Actor A ∩ Actor B`)** | **94.8%** | 34.2% | 5.6% |
