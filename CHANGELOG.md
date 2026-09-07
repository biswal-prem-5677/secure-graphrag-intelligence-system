# Changelog

All notable changes to the **Secure GraphRAG Knowledge Intelligence System** are documented in this file.

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
