# System Architecture & Design

## Overview

The **Secure GraphRAG Knowledge Intelligence System** implements a hybrid Graph-Augmented Generation pipeline specifically tailored for cybersecurity threat intelligence. Unlike naive vector-based RAG which retrieves isolated chunks, GraphRAG navigates structured relationships across nodes (e.g., Threat Actors -> Campaigns -> Malware -> Vulnerabilities -> TTPs).

---

## Key Subsystems

### 1. Ingestion & Graph Schema
- Graph model maps onto STIX 2.1 entities: `ThreatActor`, `AttackPattern`, `Malware`, `Vulnerability`, `Identity`, `Infrastructure`.
- Nodes and edges are persisted in Neo4j with Cypher query templates optimized for multi-hop neighborhood extraction.
- Automatic in-memory graph driver enables seamless execution when Neo4j is offline.
- Idempotent STIX graph seeding script (`backend/app/graph/seed.py`, `backend/scripts/seed_neo4j.py`) establishes initial threat intelligence data using Cypher `MERGE`.

### 2. Query Analyzer & Entity Resolution
- Incoming user queries are parsed for named entities, CVE identifiers, MITRE technique IDs (e.g., `T1059`), and threat actor aliases.
- Fuzzy and canonical matching maps vernacular terms to graph IDs.

### 3. Subgraph Retrieval & Context Building
- Depth-bounded traversal explores up to $N$-hops (default $k=3$) from seed nodes.
- Topological paths are condensed into a structured Markdown evidence manifest with source references.
- Context budget guard prevents token overflow before the LLM prompt is assembled.

### 4. Resilient Multi-Provider LLM Engine
- Abstract `BaseLLMProvider` contract ensures pluggable provider modularity.
- Free-first fallback ordering: `Ollama (local) -> Gemini (free-tier) -> Groq (Llama-3) -> OpenAI`.
- **Explicit Failure & Anti-Deception**: In production, if all configured providers fail or timeout, the pipeline fails explicitly with an `OperationalState.LLM_PROVIDER_ERROR` (HTTP 503 error) rather than silently returning canned mock generation. Deterministic `MockLLMProvider` is exclusively utilized when `LLM_PROVIDER=mock` for offline testing or benchmark evaluation.
- Per-provider circuit breakers isolate failing external APIs (tripping after 3 consecutive errors with 60s cooldown).

### 5. Claim-Level Verification & Confidence Engine
- Outputs are segmented into distinct factual assertions.
- Claims are mapped back to source nodes in the retrieved subgraph.
- Confidence score is computed as a weighted harmonic mean of path density, lexical overlap, and claim support.

### 6. Persistent Relational Data Layer
- **Database**: PostgreSQL 16 in production; SQLite for local development and CI (auto-detected via `DATABASE_URL`).
- **ORM**: SQLAlchemy 2.0 declarative models with 9 tables: `users`, `profiles`, `user_memories`, `session_contexts`, `saved_investigations`, `query_history`, `user_usage`, `subscriptions`, `feedbacks`.
- **Repository Pattern**: All database access is encapsulated in `backend/app/db/repository.py` with server-side `user_id` filtering on every query to enforce multi-tenant isolation.
- **Connection Pool**: Hardened pool configuration with `DB_POOL_SIZE=50`, `DB_POOL_MAX_OVERFLOW=20`, `pool_pre_ping=True`, and `pool_recycle=3600`.
- **Atomic Quota Enforcement**: Database-level conditional increments prevent concurrency race conditions under heavy multi-threaded traffic.

### 7. Multi-User Isolation & Authentication
- **Public Registration**: `POST /api/v1/auth/register` creates user + profile + free subscription atomically.
- **JWT Authentication**: Stateless HS256 tokens issued on login/register, validated via `get_current_user` dependency.
- **Anti-IDOR Protection**: All user-scoped endpoints (saved investigations, memory, profiles, usage) enforce server-side ownership checks. User A cannot access, modify, or delete User B's data.
- **Cache Isolation**: Query cache keys include `user_id` prefix to prevent cross-tenant result leakage.
- **Session Context Isolation**: Composite unique constraint `(user_id, session_id)` ensures conversational context cannot bleed between users sharing a session identifier.

### 8. Redis Sliding-Window Rate Limiting
- Production rate limiting is backed by Redis 7 (with TLS support via `rediss://`).
- Sliding-window algorithm tracks user and IP request rates without fixed-window boundary anomalies.
- Automatic in-memory fallback is active during local development and testing.

### 9. Attack Surface Hardening & Defense-in-Depth
- **Payload Size Ceiling**: `RequestBodyLimitMiddleware` rejects payloads exceeding 10MB with HTTP 413.
- **API Documentation Gating**: Swagger UI (`/docs`) and ReDoc (`/redoc`) are automatically disabled in production mode.
- **CORS Whitelist**: Explicit method and header whitelists prevent browser CSRF vectors.
- **Security Headers**: Standard OWASP headers injected on all HTTP responses (`X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`).

---

## Deployment Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Docker Compose Deployment                        │
│                                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │  PostgreSQL  │  │    Redis     │  │    Neo4j     │  │   FastAPI   │ │
│  │ (Relational  │  │ (Distributed │  │ (STIX 2.1    │  │   Backend   │ │
│  │  Multi-User) │  │ Rate Limiter)│  │ Graph Engine)│  │  (Port 8000) │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
│         │                 │                 │                 │        │
│         └─────────────────┴────────┬────────┴─────────────────┘        │
│                                    │ Internal Network                  │
│                                    v                                   │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                 Next.js Frontend (Port 3000)                     │  │
│  │           Light-Themed Web Console & Telemetry Dashboards        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

- **PostgreSQL**: User credentials, profiles, saved investigations, usage tracking, subscriptions, feedback, query history (persistent relational state).
- **Redis**: Sliding-window rate limiting tokens, transient locks, and cache coordination.
- **Neo4j**: Knowledge graph with STIX 2.1 threat intelligence entities and relationships.
- **FastAPI Backend**: GraphRAG engine, LLM orchestration, API endpoints, authentication.
- **Next.js Frontend**: 15-route production UI with login, dashboard, billing, observability, and admin pages.
