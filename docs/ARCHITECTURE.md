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

### 6. Persistent Relational Data Layer
- **Database**: PostgreSQL 16 in production; SQLite for local development and CI (auto-detected via `DATABASE_URL`).
- **ORM**: SQLAlchemy 2.0 declarative models with 8 tables: `users`, `profiles`, `user_memories`, `session_contexts`, `saved_investigations`, `user_usage`, `subscriptions`, `feedbacks`.
- **Repository Pattern**: All database access is encapsulated in `backend/app/db/repository.py` with server-side `user_id` filtering on every query to enforce multi-tenant isolation.
- **Schema Initialization**: `init_db()` is called during application lifespan startup, creating all tables via `Base.metadata.create_all()`.

### 7. Multi-User Isolation & Authentication
- **Public Registration**: `POST /api/v1/auth/register` creates user + profile + free subscription atomically.
- **JWT Authentication**: Stateless HS256 tokens issued on login/register, validated via `get_current_user` dependency.
- **Anti-IDOR Protection**: All user-scoped endpoints (saved investigations, memory, profiles, usage) enforce server-side ownership checks. User A cannot access, modify, or delete User B's data.
- **Cache Isolation**: Query cache keys include `user_id` prefix to prevent cross-tenant result leakage.
- **Session Context Isolation**: Composite unique constraint `(user_id, session_id)` ensures conversational context cannot bleed between users sharing a session identifier.

---

## Deployment Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Docker Compose                     │
│                                                     │
│  ┌───────────┐  ┌───────────┐  ┌──────────────────┐│
│  │ PostgreSQL │  │  Neo4j    │  │  FastAPI Backend  ││
│  │ (Users,   │  │ (Knowledge│  │  (GraphRAG +      ││
│  │  State)   │  │  Graph)   │  │   LLM Engine)     ││
│  └───────────┘  └───────────┘  └──────────────────┘│
│                                                     │
│  ┌──────────────────────────────────────────────────┤
│  │  Next.js Frontend (Port 3000)                    │
│  └──────────────────────────────────────────────────┤
└─────────────────────────────────────────────────────┘
```

- **PostgreSQL**: User credentials, profiles, saved investigations, usage tracking, subscriptions, feedback (persistent relational state).
- **Neo4j**: Knowledge graph with STIX 2.1 threat intelligence entities and relationships.
- **FastAPI Backend**: GraphRAG engine, LLM orchestration, API endpoints, authentication.
- **Next.js Frontend**: 15-route production UI with login, dashboard, billing, observability, and admin pages.

