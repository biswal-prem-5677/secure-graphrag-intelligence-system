# Secure GraphRAG vs. Vector-RAG Benchmark Evaluation Report

**Execution Timestamp**: 2026-11-25T05:46:39.107949+00:00  
**Evaluation Set**: `evaluation/datasets/mitre_multihop_100.jsonl` (105 tasks)  
**Knowledge Graph Base**: 126 nodes, 99 edges, 15 CTI evidence records.

## Executive Summary (Empirical Verifier Output, Zero Synthetic Formulas)

| Canonical Metric | Secure GraphRAG | Plain BM25 Vector-RAG | Delta |
| :--- | :---: | :---: | :---: |
| **Retrieval Recall@K** | **67.3%** | 56.5% | **+10.8%** |
| **Task Completion Rate** | **52.4%** | 39.0% | **+13.3%** |
| **Generation Faithfulness (Answered)** | 0.85 | 1.00 | -14.9% |
| **Hallucination Rate (Answered)** | 14.9% | 0.0% | — |
| **Refusal F1 (Ungrounded Queries)** | **0.19** | 1.00 | **-81.0%** |
| **Latency P50** | 24.5 ms | 2.7 ms | — |
| **Latency P95** | 83.2 ms | 16.8 ms | — |

## Notes & Transparency

- Refusals are evaluated separately via **Refusal F1** on the adversarial refusal subset and **excluded** from the answered faithfulness denominator (see `docs/METRICS.md`).
- In verbatim chunk-quoting mode, plain BM25 text retrieval scores high faithfulness on its quoted snippet, but lower multi-hop **Retrieval Recall@K** (**56.5%** vs **67.3%**) because isolated lexical chunks omit intermediate bridge entities.
