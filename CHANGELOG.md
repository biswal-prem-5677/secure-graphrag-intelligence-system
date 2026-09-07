# Changelog

All notable changes to the **Secure GraphRAG Knowledge Intelligence System** are documented in this file.

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
