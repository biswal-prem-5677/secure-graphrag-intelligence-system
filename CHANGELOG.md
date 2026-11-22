# Changelog

All notable changes to the **Secure GraphRAG Knowledge Intelligence System** are documented in this file.

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
