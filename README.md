# Secure GraphRAG Knowledge Intelligence System

[![CI Build](https://github.com/biswal-prem-5677/secure-graphrag-intelligence-system/actions/workflows/ci.yml/badge.svg)](https://github.com/biswal-prem-5677/secure-graphrag-intelligence-system/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111.0-emerald.svg)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-14.2-black.svg)](https://nextjs.org/)

Production-grade GraphRAG cybersecurity threat-intelligence investigation platform featuring grounded reasoning, multi-hop Neo4j traversal, explainable confidence scoring, and strict anti-hallucination guardrails.

---

## Key Features

- **Multi-Hop Graph Traversal**: Deep entity and relationship discovery across MITRE ATT&CK®, STIX 2.1, and custom threat models with automatic in-memory fallback.
- **Resilient LLM Routing**: Dynamic fallback chain supporting **Google Gemini**, **Groq**, **Ollama**, and **OpenAI**, with deterministic mock provider for zero-credential test pipelines.
- **Deterministic Anti-Hallucination**: Immediate short-circuiting on `EMPTY_RETRIEVAL` without invoking the LLM, paired with claim-level evidence grounding.
- **M1–M5 AI Quality Framework**: Automated metrics for Task Completion (M1), Faithfulness (M2), Hallucination Rate & Calibration (M3), Cost per Task (M4), and Latency P95 (M5).
- **Enterprise Defense & Security**: Token budget guards, input sanitization against prompt injection, circuit breaker failover, and JWT-authenticated session security.
- **Clean Light-Themed Web Console**: Responsive Next.js interface with live query console, usage billing, real-time observability telemetry, and evaluation runners.

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
|  | - Rate Limiter     |   | - Context Builder     |   | - Memory Store      |  |
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
- Docker & Docker Compose (optional for containerized setup)

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
To run both the Neo4j graph database and the backend service:
```bash
docker-compose up --build -d
```

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

---

## Evaluation Suite (M1–M5)

Run the automated evaluation benchmark:
```bash
python -m pytest evaluation/runners/run_full_eval.py -v
```

| Metric | Name | Target | Description |
|---|---|---|---|
| **M1** | Retrieval Precision | > 85% | Entity and path recovery accuracy across ground truth tasks |
| **M2** | Generation Faithfulness | > 90% | Percentage of generated claims grounded in retrieved graph context |
| **M3** | Confidence Calibration | < 0.15 | Brier calibration score comparing model confidence vs correctness |
| **M4** | Latency P95 | < 2500ms | 95th percentile end-to-end response time under load |
| **M5** | Cost Per Task | < $0.005 | Average token and inference expenditure per resolved query |

---

## Test Suite

Execute the full suite of unit, integration, and security tests:
```bash
pytest backend/tests/ -v
```

Run load and performance tests using Locust:
```bash
locust -f load_tests/locustfile.py --headless -u 20 -r 5 -t 1m --host http://localhost:8000
```

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) and [`NOTICE.md`](NOTICE.md) for full licensing terms and upstream software attributions.
