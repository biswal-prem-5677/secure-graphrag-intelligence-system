# System Limitations & Engineering Boundaries

This document provides a transparent, detailed disclosure of current system limitations, known architectural tradeoffs, and performance boundaries in the **Secure GraphRAG Knowledge Intelligence System**.

---

## 1. Retrieval & Graph Traversal Boundaries

1. **High-Degree Hub Node Expansion**:
   - Central entities such as `Cobalt Strike` ($S0154$) or `Command and Scripting Interpreter` ($T1059$) connect to dozens of distinct threat actors and malware families.
   - Without dynamic degree-capping and relationship filtering, unconstrained 3-hop and 4-hop traversals through hub nodes can lead to exponential path expansion, causing high token consumption and noisy context.
2. **Offline Fallback vs. Live Neo4j**:
   - In offline test mode (or when Neo4j is offline), the system falls back to an in-memory STIX 2.1 graph structure.
   - While the in-memory fallback guarantees 100% test pass rates without external dependencies, full-scale variable-length Cypher traversal optimization and parallel index lookups require a live, running Neo4j instance.
3. **Lexical vs. Dense Hybrid Retrieval**:
   - The plain baseline utilizes lexical BM25/TF-IDF chunk retrieval over threat intelligence documents. While BM25 excels at exact identifier matching (CVE numbers, malware names), dense embeddings (FAISS/Contriever) perform better on abstract semantic descriptions.

---

## 2. Verification & Guardrail Boundaries

1. **Heuristic vs. Neural Natural Language Inference (NLI)**:
   - The current claim verifier performs structural entity candidate extraction and graph-topological path validation.
   - Complex nuanced sentence structures involving negations ("APT28 did not deploy...") or speculative hedging ("might have been affiliated with...") are evaluated based on structural presence rather than deep cross-encoder natural language inference.
2. **Deterministic Mock vs. Production LLM Generation**:
   - The local test harness executes against a deterministic mock provider to enable fast, zero-credential CI quality gates.
   - Evaluation metrics computed under `LLM_PROVIDER=mock` test the deterministic logic of the pipeline and guardrails, but do not reflect the generation variance of commercial foundation models (Gemini 2.5, GPT-4o, Llama 3.3).

---

## 3. Identity & Deployment Scope

1. **Single-Node In-Memory Cache**:
   - In local development mode, query caching operates via an in-memory TTL dictionary per process.
   - For multi-worker production deployments, Redis clustering with TLS (`rediss://`) must be enabled to prevent cache fragmentation across worker processes.
2. **SaaS Scaffolding vs. AI Core**:
   - User subscriptions, daily query quotas, and Stripe webhook scaffolding exist as production SaaS scaffolding. They provide rate limits and multi-user isolation, but are separate from the core GraphRAG retrieval and verification engine.
