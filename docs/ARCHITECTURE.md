# System Architecture & Design

## Overview

The **Secure GraphRAG Knowledge Intelligence System** implements a hybrid Graph-Augmented Generation pipeline specifically tailored for cybersecurity threat intelligence. Unlike naive vector-based RAG which retrieves isolated chunks, GraphRAG navigates structured relationships across nodes (e.g., Threat Actors -> Campaigns -> Malware -> Vulnerabilities -> TTPs).

---

## Key Subsystems

### 1. Ingestion & Graph Schema
- Graph model maps onto STIX 2.1 entities: `ThreatActor`, `AttackPattern`, `Malware`, `Vulnerability`, `Identity`, `Infrastructure`.
- Nodes and edges are persisted in Neo4j with Cypher query templates optimized for multi-hop neighborhood extraction.
- Automatic in-memory graph driver enables seamless execution when Neo4j is offline.

### 2. Query Analyzer & Entity Resolution
- Incoming user queries are parsed for named entities, CVE identifiers, MITRE technique IDs (e.g., `T1059`), and threat actor aliases.
- Fuzzy and canonical matching maps vernacular terms to graph IDs.

### 3. Subgraph Retrieval & Context Building
- Depth-bounded traversal explores up to $N$-hops (default $k=3$) from seed nodes.
- Topological paths are condensed into a structured Markdown evidence manifest with source references.
- Context budget guard prevents token overflow before the LLM prompt is assembled.

### 4. Resilient Multi-Provider LLM Engine
- Abstract `LLMProvider` contract ensures modularity.
- Provider fallback chain: `Mock -> Ollama -> Groq -> Gemini -> OpenAI`.
- Circuit breakers isolate failing external APIs and trigger graceful degradation.

### 5. Claim-Level Verification & Confidence Engine
- Outputs are segmented into distinct factual assertions.
- Claims are mapped back to source nodes in the retrieved subgraph.
- Confidence score is computed as a weighted harmonic mean of path density, lexical overlap, and claim support.
