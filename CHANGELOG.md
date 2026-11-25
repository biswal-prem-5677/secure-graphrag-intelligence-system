# Changelog

All notable changes to the **Secure GraphRAG Knowledge Intelligence System** are documented in this file.

## [1.6.0] - 2026-11-25

### Added (Audit Remediation — Phase 4: Claim Verifier v2, Platt Calibration & Untrusted Context Boundaries)
- **Claim Verifier v2 (`backend/app/evaluation/claim_verifier.py`)**:
  - Added `StructuredClaim(subject, relation, object, evidence_id, negated)` verification alongside free-text assertion checking.
  - Enforced strict entity grounding (unknown proper nouns fail by default), **directed edge validation** (catching direction flips like `"Cobalt Strike uses APT28"`), **relation type matching** (catching relation swaps like `"APT28 mitigates Cobalt Strike"`), **negation contradiction detection**, and **verbatim temporal/CVE grounding**.
- **160-Claim Adversarial Verifier & Calibration Benchmark (`evaluation/runners/run_verifier_calibration_eval.py`)**:
  - Generated `evaluation/datasets/verifier_claims_160.jsonl` across 8 categories (60 dev / 100 frozen held-out test).
  - Achieved **99.0% Accuracy** `[97.0–100.0% 95% CI]`, **100.0% Hallucination Precision**, **98.7% Hallucination Recall**, **0.993 F1**, **100.0% Invented-Entity Recall**, and **0.0773 Brier Score** (target `< 0.15`).
  - Added `backend/tests/unit/test_verifier_v2.py` verifying structured triples, direction reversals, negation contradictions, and calibration monotonicity.

### Changed
- **Platt-Calibrated Continuous Confidence (`backend/app/evaluation/confidence.py`)**:
  - Replaced categorical threshold buckets with continuous logistic probability scoring over verifier support, path density, evidence provenance confidence, and entity coverage.
  - Removed duplicate confidence scoring heuristics from `openai_provider.py` and `groq_provider.py` so `ConfidenceScorer` acts as the single authoritative calibrator downstream of `ClaimVerifier`.
- **Delimited Untrusted Prompt Contract (`backend/app/llm/prompts.py`)**:
  - Wrapped retrieved graph context inside `<untrusted_context>...</untrusted_context>` XML boundaries with explicit prompt-injection resistance instructions and structured claim formatting.

## [1.5.0] - 2026-11-25

### Added (Audit Remediation — Phase 3: Non-Circular Programmatic Evaluation & 3-System Baseline)
- **Programmatic Multi-Hop Benchmark Generator (`scripts/build_attack_benchmark.py`)**:
  - Generated **220 non-circular multi-hop tasks** directly from the Official MITRE ATT&CK® Enterprise v20.1 NetworkX graph without leaking answer entities in questions:
    - 70 × 2-hop tasks (`ThreatActor -> Software -> Technique`)
    - 70 × 3-hop tasks (`ThreatActor -> Software -> Technique <- MITIGATES <- Mitigation`)
    - 40 × Set-Intersection tasks (`Actor A ∩ Actor B` shared techniques)
    - 40 × Unanswerable out-of-distribution refusal tasks
  - Split deterministically (`seed=42`) into `evaluation/datasets/attack_v20_1_dev.jsonl` (80 tasks) and `evaluation/datasets/attack_v20_1_test.jsonl` (140 frozen held-out tasks).
- **3-System Head-to-Head Empirical Benchmark (`evaluation/runners/run_vector_baseline.py`)**:
  - Evaluates **Secure GraphRAG**, **Plain BM25 Chunk RAG**, and **Dense LSA Vector-RAG** (128-dim TruncatedSVD L2 cosine over TF-IDF) using **one shared exact canonical matcher** and the same `ClaimVerifier`.
  - Computes bootstrap 95% confidence intervals (`n=1000`, `seed=42`) and per-hop breakdowns:
    - Overall Retrieval Recall@K: **68.7%** `[62.7–74.6%]` (GraphRAG) vs **8.5%** (BM25) vs **2.3%** (Dense LSA)
    - 3-Hop Recall: **60.8%** (GraphRAG) vs **0.0%** (BM25) vs **0.0%** (Dense LSA)
    - Refusal F1: **0.93** (GraphRAG) vs **0.00** (BM25 / Dense LSA)
- **Automated README Sync (`scripts/sync_readme_metrics.py`)**:
  - Generates the `README.md` comparative benchmark table directly from `evaluation/results/baseline_comparison.json`.

### Changed
- Fixed `QueryService` to pass `max(request.max_hops, analysis.max_hops)` to `GraphRetriever.retrieve_subgraph()`.
- Updated `GraphRetriever.retrieve_subgraph()` to traverse incoming `MITIGATES` and `ATTRIBUTED_TO` edges when mitigation/attribution intent is present.
- Filtered generic lowercase nouns (`malware`, `vulnerability`, `technique`, `mitigation`) from noisy entity extraction in `QueryAnalyzer`.

## [1.4.0] - 2026-11-25

### Added (Audit Remediation — Phase 2: Official Data & Real Cypher Traversal)
- **Official MITRE ATT&CK® Enterprise v20.1 STIX 2.1 Pipeline (`scripts/ingest_attack.py`)**:
  - Replaced synthetic hand-written threat JSON with the pinned official Enterprise ATT&CK v20.1 STIX 2.1 bundle (`SHA-256: 539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5`), compiling **1,827 entities**, **20,957 directed STIX relationships**, and **22,299 provenance-linked evidence records** into `backend/app/graph/attack_enterprise_v20_1.json.gz`.
  - Created `docs/DATA.md` recording data provenance, bundle SHA-256 checksum, entity/edge counts, and ATT&CK® terms of use.
- **True Parameterized Cypher Multi-Hop Traversal & Indexed NetworkX Fallback**:
  - Rewrote `GraphRetriever.retrieve_subgraph()` to execute typed, directed, depth-bounded variable-length Cypher path queries (`MATCH p = (seed)-[rels*1..{depth}]->(target)`) ordered by hop length and minimum confidence when Neo4j is live.
  - Replaced repeated per-query disk JSON reading and $O(N \times E)$ edge loops with a cached `networkx.MultiDiGraph` index loaded once, enforcing directed traversal, `intended_rels` filtering, and hub-degree capping (`hub_degree_cap=15`).
- **Full-Text Search & Fuzzy Entity Resolution**:
  - Added `db.index.fulltext.queryNodes("entityFulltext", ...)` Cypher lookup alongside `difflib` fuzzy similarity matching, ATT&CK alias indexing (`Fancy Bear` -> `APT28`), and external ID matching (`G0007`, `S0154`, `T1055`, `M1049`) in `GraphRetriever` and `QueryAnalyzer`.
  - Provenance-linked evidence retrieval now resolves citations directly via edge `source_id`s rather than blind substring scans.
- **Verification Tests**:
  - Added `backend/tests/unit/test_cypher_traversal.py` verifying parameterized Cypher variable-length path execution, directed BFS filtering, hub-degree capping, and fuzzy/alias entity resolution.

## [1.3.1] - 2026-11-25

### Changed (Audit Remediation — Phase 1)
- **Empirical Evaluation Integrity**:
  - Removed all formulaic baseline scoring heuristics (`max(0.20, recall * 0.85)`) from `evaluation/runners/run_vector_baseline.py`. Plain Vector-RAG answers are now evaluated directly through `ClaimVerifier.verify_answer()`.
  - Isolated evaluation artifacts per run into `evaluation/results/runs/<run_id>/` and separated canonical files (`full_eval_results.json` vs `baseline_comparison.json` / `baseline_comparison.md`) so runs no longer overwrite each other.
  - Separated refusal evaluation (`refusal_precision`, `refusal_recall`, `refusal_f1`) from answered-query faithfulness in `ClaimVerificationResult.is_refusal` and `run_vector_baseline.py` so refusals do not inflate faithfulness scores.
- **Credential & Identity Hygiene**:
  - Removed all hardcoded default password literals from `backend/app/security/auth.py` and `backend/app/core/config.py`.
  - Removed import-time database user seeding side-effects in `security/auth.py` and silent user auto-creation side-effects in `db/repository.py`.
  - Added explicit admin onboarding CLI utility `backend/app/cli.py` (`python -m app.cli create-admin`).
- **Metrics & Limitations Transparency**:
  - Created `docs/METRICS.md` establishing canonical metric definitions (`retrieval_recall_at_k`, `generation_faithfulness`, `refusal_f1`, etc.).
  - Created `docs/LIMITATIONS.md` disclosing current graph traversal, NLI verification, and deterministic mock limitations.

## [1.3.0] - 2026-11-24

### Added
- **Public MITRE ATT&CK STIX 2.1 Knowledge Base & Ingestion**:
  - Ingested 110 real MITRE ATT&CK entities (20 threat actors including APT28, APT29, Lazarus Group, Sandworm Team, Volt Typhoon, Scattered Spider, FIN7; 24 malware and tools including Cobalt Strike, Mimikatz, BlackCat, Industroyer, HermeticWiper; 36 ATT&CK techniques; 10 CVEs; 10 target sectors; 10 mitigations), 87 verified relationships, and 12 primary source CTI evidence records into `backend/app/graph/mitre_attack_stix21.json`.
  - Built standalone STIX 2.1 Neo4j batch ingester `backend/app/graph/mitre_ingest.py` with schema indexing and MERGE queries.
  - Enhanced `GraphRetriever` to dynamically resolve both canonical test fixtures and MITRE ATT&CK entities seamlessly.
- **105-Query Multi-Hop Benchmark & Comparative Plain Vector-RAG Baseline**:
  - Curated `evaluation/datasets/mitre_multihop_100.jsonl` with 105 multi-hop threat intelligence tasks across 2-hop, 3-hop, 4-hop actor-tool-technique chains, and adversarial ungrounded refusal probes.
  - Implemented `evaluation/runners/run_vector_baseline.py` comparing Secure GraphRAG against a plain BM25 Vector-RAG baseline.
- **Interactive Live Investigation Demo CLI**:
  - Created `scripts/demo_investigation.py` showcasing end-to-end multi-hop graph traversal, cross-campaign lateral movement analysis, and anti-hallucination guardrails with interactive investigation query support.
- **Hand-Labeled Claim Verifier Benchmark**:
  - Added `backend/tests/unit/test_claim_verifier_benchmark.py` measuring verifier precision, recall, and F1 across 23 hand-labeled threat intelligence claims without artificial blacklists.

### Changed
- **Anti-Hallucination Claim Verifier Overhaul (Zero Test Leakage)**:
  - Completely removed hardcoded blacklist tokens (`"stuxnet"`, `"fictional_alien_botnet"`, `"2029"`, `"centrifuges"`) and weak 15% word overlap heuristics from `backend/app/evaluation/claim_verifier.py`.
  - Replaced with structural candidate entity extraction (regex patterns for CVEs, IPs, ATT&CK IDs, proper noun phrases) and entity-relation topological grounding against retrieved graph context and CTI evidence records.
- **Explicit LLM Provider Failure Handling & Documentation Alignment**:
  - Updated `backend/app/llm/factory.py` so multi-provider fallback chains fail explicitly with `OperationalState.LLM_PROVIDER_ERROR` (HTTP 503) instead of silently returning mock answers when real providers are exhausted. Mock provider is restricted strictly to local dev/test environments with `LLM_PROVIDER=mock`.
  - Corrected `docs/ARCHITECTURE.md` Section 4 to reflect the accurate fallback chain: `Ollama (local) -> Gemini (free-tier) -> Groq -> OpenAI -> Explicit Error`.
- **Clean Clone Resilience & Evaluation Runner Fix**:
  - Enhanced `backend/app/db/repository.py` to auto-seed default user records in non-production environments, eliminating `IntegrityError: FOREIGN KEY constraint failed` when running tests or benchmarks on fresh databases.
  - Updated `evaluation/runners/run_full_eval.py` to initialize tables, seed default users, and output to `evaluation/results/` cleanly on fresh clones.
  - Updated `UsageTracker` and `QueryService` to grant unlimited quota for evaluation runners (`eval_user`, `admin`).
  - Added 30-second cooldown on failed Neo4j connection attempts in `Neo4jClient.is_healthy()` to eliminate connection timeouts during offline evaluation runs.

## [1.2.0] - 2026-09-08

### Added
- **Production Hardening & Concurrency Safety**:
  - Atomic database-level conditional quota enforcement in `UsageRepository.check_and_increment` preventing race conditions under high concurrency.
  - Connection pool configuration: `DB_POOL_SIZE=50`, `DB_POOL_MAX_OVERFLOW=20`, `pool_pre_ping=True`, and `pool_recycle=3600`.
  - Redis sliding-window rate limiter with `rediss://` TLS support and fail-closed production semantics.
  - `RequestBodyLimitMiddleware`: 10MB payload ceiling returning HTTP 413 to prevent memory exhaustion attacks.
  - Production Swagger UI gating: `docs_url` and `redoc_url` disabled when `ENVIRONMENT=production`.
  - Hardened CORS configuration with method and header whitelists.
  - Standalone, idempotent Neo4j STIX threat intelligence seeder (`backend/app/graph/seed.py`, `backend/scripts/seed_neo4j.py`).
  - Production environment template `.env.production.example`.
- **Automated Production Acceptance & Concurrency Tests**:
  - `test_production_acceptance.py`: 8 tests covering fail-closed configuration, admin RBAC, sandbox upgrade removal, query history isolation, email format validation, and payload size limits.
  - `test_concurrency_and_scale.py`: 3 tests verifying multi-threaded atomic quota enforcement, connection pool stability with 50 workers, and parallel history writes.
  - `test_neo4j_lifecycle.py` and `test_neo4j_seed.py`: 12 tests covering Neo4j connection lifecycle, driver termination, retry dynamics, and idempotent graph seeding.
  - Full automated test suite expanded to 107 tests (all passing).
- **Admin AI Quality & Benchmark Suite API**:
  - `GET /api/v1/admin/evaluations`: Serves current automated benchmark evaluation metrics (M1-M5).
  - `POST /api/v1/admin/evaluations/run`: Triggers on-demand evaluation execution with RBAC protection.
- **Frontend End-to-End Authentication Unification**:
  - Unified `auth_token` and `token` storage across Dashboard, Billing, Profile, and Quality admin consoles.
  - Dashboard query console gracefully handles authentication requirements with actionable guidance.

### Changed
- `pyproject.toml` & `requirements.txt`: Pinned `starlette>=0.37.2,<0.39.0` and added `asyncio_default_fixture_loop_scope = "function"` to resolve FastAPI routing compatibility and pytest deprecation warnings.
- `backend/app/schemas/schemas.py` & `backend/app/api/health.py`: Added `llm_provider` and `neo4j_connected` attributes to `HealthResponse` for live system status inspection.
- `frontend/next.config.ts`: Added dynamic backend routing via `BACKEND_INTERNAL_URL` with local dev fallback.
- `docker-compose.yml`: Integrated Redis service, mandatory `SECRET_*` environment variable enforcement, and `BACKEND_INTERNAL_URL`.
- `frontend/app/billing/page.tsx`: Replaced `/api/v1/billing/usage` with canonical `/api/v1/billing/subscription` endpoint with bearer auth.
- `backend/app/api/billing.py`: Permanently removed developer sandbox self-upgrade/downgrade endpoints.
- `backend/app/main.py`: Serialized validation exceptions using `jsonable_encoder`.

## [1.1.0] - 2026-09-07

### Added
- **Production PostgreSQL Persistence Layer**:
  - SQLAlchemy 2.0 ORM with automatic SQLite fallback for local dev and CI.
  - 8 persistent database tables: `users`, `profiles`, `user_memories`, `session_contexts`, `saved_investigations`, `user_usage`, `subscriptions`, `feedbacks`.
  - Repository pattern with encapsulated CRUD operations and server-side user isolation.
- **Public User Registration & Authentication Lifecycle**:
  - `POST /api/v1/auth/register`: Open registration with username/email uniqueness, bcrypt hashing, and instant JWT session.
  - `POST /api/v1/auth/login`: Credential validation with disabled-account guard.
  - `GET /api/v1/auth/me`: Sanitized user profile (no password/hash exposure).
  - `POST /api/v1/auth/logout`: Session acknowledgement endpoint.
- **Multi-User Isolation & Anti-IDOR Protection**:
  - All saved investigations, memories, profiles, usage, and subscriptions enforce server-side `user_id` filtering.
  - Session context isolation via composite `(user_id, session_id)` unique constraint.
  - Query cache keys scoped by `user_id` to prevent cross-tenant result leakage.
- **Multi-User Isolation Test Suite** (`test_multi_user_isolation.py`):
  - 6 dedicated tests covering registration, IDOR on saved investigations, memory isolation, profile isolation, usage/subscription isolation, and cache isolation.
- **Frontend Login/Register Page** (`/login`):
  - Sign-in and registration forms with JWT token management via `localStorage`.
  - Sidebar navigation updated with authentication link.
- **Frontend Dockerfile**: Multi-stage production build for Next.js containerization.
- **Docker Compose PostgreSQL Service**: `postgres:16-alpine` with persistent `postgres_data` volume and healthcheck.

### Changed
- `backend/app/main.py`: Calls `init_db()` during application lifespan startup.
- `backend/app/core/config.py`: Added `DATABASE_URL`, `SEED_DEFAULT_USERS`, and `ENVIRONMENT` settings.
- `backend/app/security/auth.py`: `seed_default_users()` now guards with `SEED_DEFAULT_USERS` flag and wraps in error handling.
- `docker-compose.yml`: Added PostgreSQL + frontend services, `DATABASE_URL` environment variable for backend.
- `.env.example`: Added `DATABASE_URL` and `SEED_DEFAULT_USERS` configuration documentation.
- `backend/tests/conftest.py`: Added test database isolation fixture with per-test table reset and re-seeding.
- Test count increased from 75 to 81 (all passing).

## [1.0.0] - 2026-09-07

### Added
- **Core GraphRAG Engine**:
  - Multi-hop traversal using Neo4j with fallback in-memory graph driver.
  - Query analyzer parsing threat entities, ATT&CK techniques, and threat actors.
  - Subgraph context builder and claim verification pipeline.
- **Resilient Multi-Provider LLM System**:
  - Abstract provider interface with concrete drivers for Gemini, Groq, Ollama, OpenAI, and Mock.
  - Circuit breaker failover (`FallbackMultiProvider`) automatically escalating through the free-first provider chain.
- **AI Quality & Evaluation Suite (M1–M5)**:
  - M1: Task Completion Rate & Precision@K.
  - M2: Faithfulness Score with claim-level evidence grounding.
  - M3: Hallucination Rate & confidence calibration scoring (Brier score).
  - M4: Cost per task tracker (prompt, completion, embedding breakdown).
  - M5: Latency P95 benchmarking and escalation rate.
- **Defense & Guardrails**:
  - Short-circuit on empty retrieval (`EMPTY_RETRIEVAL`) preventing LLM hallucination.
  - Token and cost budget guards preventing runaway inference.
  - Rate limiting, timing middleware, and input sanitization against prompt injection.
- **Modern Light-Themed Web Frontend**:
  - Built with Next.js 14 App Router, TypeScript, and clean CSS styling.
  - Live query console, usage & billing, observability dashboard, and AI evaluation manager.
- **Enterprise Testing & CI**:
  - Over 29 unit, integration, and security test files.
  - Locust load testing suite.
  - GitHub Actions automated CI workflow.
