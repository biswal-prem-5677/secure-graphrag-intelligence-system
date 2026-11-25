# Secure GraphRAG Knowledge Intelligence System

[![CI Build](https://github.com/biswal-prem-5677/secure-graphrag-intelligence-system/actions/workflows/ci.yml/badge.svg)](https://github.com/biswal-prem-5677/secure-graphrag-intelligence-system/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-emerald.svg)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-16.3+-black.svg)](https://nextjs.org/)

Production-grade GraphRAG cybersecurity threat-intelligence investigation platform featuring grounded reasoning, multi-hop Neo4j traversal, explainable confidence scoring, and strict anti-hallucination guardrails.

---

## Key Features

- **Multi-Hop Graph Traversal**: Deep entity and relationship discovery across MITRE ATT&CK®, STIX 2.1, and custom threat models with automatic in-memory fallback.
- **Resilient LLM Routing**: Dynamic fallback chain supporting **Google Gemini**, **Groq**, **Ollama**, and **OpenAI**, with deterministic mock provider for zero-credential test pipelines.
- **Deterministic Anti-Hallucination**: Immediate short-circuiting on `EMPTY_RETRIEVAL` without invoking the LLM, paired with claim-level evidence grounding.
- **M1–M5 AI Quality Framework**: Automated metrics for Task Completion (M1), Faithfulness (M2), Hallucination Rate & Calibration (M3), Cost per Task (M4), and Latency P95 (M5).
- **Enterprise Defense & Security**: Token budget guards, input sanitization against prompt injection, circuit breaker failover, and JWT-authenticated session security.
- **Production Multi-User Persistence**: PostgreSQL-backed user management, saved investigations, usage tracking, and subscriptions with SQLAlchemy 2.0 ORM (SQLite auto-fallback for development).
- **Multi-User Isolation & Anti-IDOR**: Server-side ownership enforcement on all user-scoped data with session context isolation and cache key scoping.
- **Public Registration & Authentication**: Open user registration with bcrypt password hashing, JWT token issuance, and complete auth lifecycle (`register`, `login`, `me`, `logout`).
- **Distributed Redis Rate Limiting**: Sliding-window rate limiter with `rediss://` TLS support and fail-closed production semantics.
- **Clean Light-Themed Web Console**: Responsive Next.js 16 interface with live query console, login/register, usage billing, real-time observability telemetry, and evaluation runners.

---

## Architecture Overview

```
                      +------------------------------------------+
                      |         Next.js Web Console (App Router) |
                      |  (Dashboard, Observability, AI Quality)  |
                      +--------------------+---------------------+
                                           | HTTP / REST
                                           v
+--------------------------------------------------------------------------------+
|                         FastAPI Core Application Server                        |
|                                                                                |
|  +--------------------+   +-----------------------+   +---------------------+  |
|  | Security / Auth    |   | Query Orchestration   |   | Telemetry / Cache   |  |
|  | - JWT validation   |   | - Query Analyzer      |   | - Prometheus metrics|  |
|  | - Redis Limiter    |   | - Context Builder     |   | - Memory Store      |  |
|  | - Input sanitizer  |   | - Claim Verifier      |   | - TTL query cache   |  |
|  +--------------------+   +-----------+-----------+   +---------------------+  |
|                                       |                                        |
|                 +---------------------+---------------------+                  |
|                 |                                           |                  |
|                 v                                           v                  |
|  +------------------------------+            +------------------------------+  |
|  | Neo4j Graph Retrieval        |            | Resilient Multi-Provider LLM |  |
|  | - Multi-hop Cypher traversal |            | - Gemini / Groq / OpenAI     |  |
|  | - In-memory fallback graph   |            | - Ollama (Local) / Mock      |  |
|  +------------------------------+            +------------------------------+  |
+--------------------------------------------------------------------------------+
```

---

## Quickstart Guide

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ (for frontend)
- Docker & Docker Compose (recommended for full-stack deployment)
- PostgreSQL 16+ (production) or SQLite (development, auto-detected)
- Redis 7+ (production rate limiting) or in-memory (development)

### 2. Installation

Clone the repository:
```bash
git clone https://github.com/biswal-prem-5677/secure-graphrag-intelligence-system.git
cd secure-graphrag-intelligence-system
```

Install backend dependencies:
```bash
pip install -r requirements.txt
```

Configure your environment:
```bash
cp .env.example .env
# Edit .env with your desired settings (or leave LLM_PROVIDER=mock for offline test mode)
```

### 3. Running with Docker Compose
Launches PostgreSQL, Redis, Neo4j, FastAPI backend, and Next.js frontend:
```bash
docker-compose up --build -d
```
Services: `postgres` (5432), `redis` (6379), `neo4j` (7474/7687), `backend` (8000), `frontend` (3000).

### 4. Running Locally

**Start the FastAPI Backend:**
```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger docs will be available at [http://localhost:8000/docs](http://localhost:8000/docs).

**Start the Next.js Frontend:**
```bash
cd frontend
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### 5. Seeding the Neo4j Threat Intelligence Graph
Populate Neo4j with canonical STIX 2.1 threat actors, campaigns, malware, vulnerabilities, and MITRE ATT&CK techniques:
```bash
# Locally:
python backend/scripts/seed_neo4j.py

# Inside Docker:
docker compose exec backend python scripts/seed_neo4j.py
```

---

## Live Demo & Investigation CLI

Run the interactive live investigation demonstration (requires zero configuration, runs offline with built-in MITRE ATT&CK STIX 2.1 knowledge base):

```bash
# Automated walkthrough of multi-hop investigations and anti-hallucination defense:
python scripts/demo_investigation.py

# Interactive investigation shell:
python scripts/demo_investigation.py --interactive
```

---

## Comparative Benchmark: Secure GraphRAG vs. Plain Vector-RAG

Evaluates multi-hop retrieval and grounded reasoning across **105 threat intelligence tasks** (`evaluation/datasets/mitre_multihop_100.jsonl`) traversing 2-hop to 4-hop actor-tool-technique chains and adversarial ungrounded refusal probes.

Both pipelines are benchmarked head-to-head on the same question set:
- **Secure GraphRAG**: Cypher-based graph retrieval with topological path discovery and atomic claim verification.
- **Plain Vector-RAG Baseline**: Lexical BM25 chunk retrieval over threat intelligence documents with answer synthesis verified by the same claim verification engine.

```bash
python evaluation/runners/run_vector_baseline.py
```

Outputs are isolated per run under `evaluation/results/runs/<run_id>/` and summarized in [`evaluation/results/baseline_comparison.md`](evaluation/results/baseline_comparison.md). Detailed scoring definitions are available in [`docs/METRICS.md`](docs/METRICS.md).

---

## Evaluation Suite

Run the automated evaluation benchmark:
```bash
python evaluation/runners/run_full_eval.py
```

| Canonical Metric | Code Identifier | Target | Scope |
|---|---|---|---|
| **Retrieval Recall@K** | `retrieval_recall_at_k` | $\ge 85\%$ | Entity & path recovery accuracy |
| **Generation Faithfulness** | `generation_faithfulness` | $\ge 90\%$ | Claims supported by graph context (answered queries) |
| **Hallucination Rate** | `hallucination_rate` | $\le 10\%$ | Claims unsupported by evidence ($1.0 - \text{faithfulness}$) |
| **Refusal F1 Score** | `refusal_f1` | $\ge 92\%$ | Accuracy on unanswerable/adversarial queries |
| **Confidence Calibration** | `calibration_error_brier` | $< 0.15$ | Brier calibration score vs correctness |
| **Latency P95** | `latency_p95_ms` | $< 2500\text{ms}$ | 95th percentile response time under load |
| **Cost Per Query** | `cost_per_query_usd` | $< \$0.005$ | Average inference expenditure per query |

---

## Test Suite

Execute the complete suite of 108 unit, integration, scale/concurrency, Neo4j lifecycle, and multi-user isolation security tests:
```bash
pytest backend/tests/ -v
```

Run load and performance tests using Locust:
```bash
locust -f load_tests/locustfile.py --headless -u 20 -r 5 -t 1m --host http://localhost:8000
```

---

## Health & Probes

| Endpoint | Type | Description |
|---|---|---|
| `GET /health` | Liveness | Verifies service responsiveness (returns status, version, LLM provider, Neo4j state) |
| `GET /ready` | Readiness | Verifies database (PostgreSQL/SQLite), Neo4j, Redis, and cache connectivity |
| `GET /metrics` | Observability | Prometheus-compatible performance, request count, latency percentiles, and cache metrics |

---

## Documentation Links

- [REST API Reference](docs/API.md)
- [System Architecture & Design](docs/ARCHITECTURE.md)
- [Data Sources & ATT&CK Provenance](docs/DATA.md)
- [Metrics Specification & Evaluation Standards](docs/METRICS.md)
- [System Limitations & Known Boundaries](docs/LIMITATIONS.md)
- [Evaluation & Benchmark Methodology](docs/EVALUATION.md)
- [Security Policy & Vulnerability Reporting](SECURITY.md)
- [Changelog](CHANGELOG.md)

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) and [`NOTICE.md`](NOTICE.md) for full licensing terms and upstream software attributions.
