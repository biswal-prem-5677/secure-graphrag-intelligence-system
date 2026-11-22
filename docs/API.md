# REST API Reference

All application endpoints are served under `/api/v1` (with `/health`, `/ready`, and `/metrics` at root level) with JSON request and response payloads.

---

## 1. Query & Investigation Endpoints

### `POST /api/v1/query`
Execute a GraphRAG threat investigation query with grounded multi-hop reasoning, confidence scoring, and anti-hallucination guardrails.

**Headers:**
- `Authorization: Bearer <token>`
- `Content-Type: application/json`

**Request Body:**
```json
{
  "query": "What attack patterns does APT29 utilize for initial compromise?",
  "session_id": "session-1234",
  "max_hops": 2,
  "bypass_cache": false
}
```

**Response Body (200 OK):**
```json
{
  "query_id": "9f3c7e82-1234-4a56-b789-0123456789ab",
  "query": "What attack patterns does APT29 utilize for initial compromise?",
  "answer": "APT29 leverages Spearphishing Attachment (T1566.001) and Valid Accounts (T1078)...",
  "confidence": "HIGH",
  "confidence_explanation": "Grounding verification confirmed 3 source entities in STIX knowledge graph.",
  "operational_state": "TASK_COMPLETED",
  "task_status": "TASK_COMPLETED",
  "escalation_action": "NONE",
  "graph_data": {
    "nodes": [
      { "id": "threat-actor--apt29", "name": "APT29", "label": "ThreatActor", "properties": {} }
    ],
    "edges": [
      { "source": "threat-actor--apt29", "target": "attack-pattern--t1566", "type": "USES", "properties": {} }
    ]
  },
  "relationship_paths": [
    {
      "source": "APT29",
      "relation": "USES",
      "target": "T1566.001",
      "evidence_ids": ["src-01"]
    }
  ],
  "evidence_records": [
    {
      "source_id": "src-01",
      "title": "MITRE ATT&CK Enterprise",
      "source_type": "stix_threat_intel",
      "confidence": 0.95,
      "summary": "APT29 observed using spearphishing attachment for initial access."
    }
  ],
  "cited_sources": ["MITRE ATT&CK Enterprise"],
  "unsupported_claims": [],
  "faithfulness_score": 1.0,
  "cached": false,
  "cost_usd": 0.00042,
  "stage_timings": {
    "validation_ms": 1.2,
    "cache_lookup_ms": 0.4,
    "query_analysis_ms": 12.1,
    "graph_retrieval_ms": 45.3,
    "context_assembly_ms": 3.2,
    "llm_generation_ms": 280.0,
    "claim_verification_ms": 15.6,
    "total_pipeline_ms": 357.8
  }
}
```

### `GET /api/v1/query/history`
Retrieve query history for the authenticated user (strictly isolated to user).

**Headers:** `Authorization: Bearer <token>`
**Query Parameters:** `limit` (int, default 50)

**Response Body (200 OK):**
```json
[
  {
    "query_id": "9f3c7e82-1234-4a56-b789-0123456789ab",
    "query": "What attack patterns does APT29 utilize?",
    "timestamp": "2026-09-08T14:32:00Z",
    "confidence": "HIGH",
    "operational_state": "TASK_COMPLETED"
  }
]
```

### `GET /api/v1/query/cache/stats`
Retrieve memory cache hit/miss ratio, eviction counts, and size metrics.

**Headers:** `Authorization: Bearer <token>`

---

## 2. Health & System Monitoring

### `GET /health`
Liveness probe for orchestrators and load balancers.
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "llm_provider": "gemini",
  "neo4j_connected": true
}
```

### `GET /ready`
Readiness probe verifying PostgreSQL, Neo4j, Redis, and LLM provider connectivity. Returns HTTP 503 if any required dependency is unavailable in production.
```json
{
  "status": "ready",
  "neo4j": "connected",
  "cache": "healthy",
  "active_llm": "mock",
  "postgres": "connected"
}
```

### `GET /metrics`
Prometheus-compatible real-time performance, request count, latency percentiles, and cache metrics.
```json
{
  "total_requests": 1420,
  "avg_latency_ms": 284,
  "p95_latency_ms": 420,
  "error_rate_percent": 0.2,
  "hit_ratio_percent": 27.0,
  "cache": {
    "hits": 384,
    "misses": 1036,
    "size": 384
  }
}
```

### `GET /api/v1/observability/health`
Public performance and health summary (no auth required).

### `GET /api/v1/observability/summary`
Full observability summary including telemetry, cost tracking, and active alerts.

---

## 3. Authentication & User Management

### `POST /api/v1/auth/register`
Public user registration. Atomically creates user, profile, and free subscription.

**Request Body:**
```json
{
  "username": "new_analyst",
  "password": "SecurePassword123!",
  "email": "analyst@example.com"
}
```

**Response Body (201 Created):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "username": "new_analyst",
  "role": "analyst"
}
```

### `POST /api/v1/auth/login`
Authenticate with credentials and obtain a JWT bearer token.

**Request Body:**
```json
{
  "username": "analyst",
  "password": "SecureAnalyst2024!"
}
```

**Response Body (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "username": "analyst",
  "role": "analyst"
}
```

### `GET /api/v1/auth/me`
Retrieve authenticated user identity (no password hash exposed).

**Response Body (200 OK):**
```json
{
  "id": "user-uuid",
  "username": "analyst",
  "email": "analyst@example.com",
  "role": "analyst",
  "disabled": false
}
```

### `POST /api/v1/auth/logout`
Acknowledge user session logout.

---

## 4. Billing & Subscription Management

### `GET /api/v1/billing/subscription`
Retrieve subscription status, plan tier, daily query count, and reset timestamp.

**Response Body (200 OK):**
```json
{
  "user_id": "analyst",
  "plan_tier": "free",
  "status": "active",
  "daily_count": 3,
  "daily_limit": 20,
  "resets_at": "2026-09-08T00:00:00Z",
  "is_stripe_configured": false
}
```

### `POST /api/v1/billing/create-checkout-session`
Create a Stripe Checkout session for Pro plan upgrade.

### `POST /api/v1/billing/webhook`
Stripe event webhook handler (verifies signature in production).

---

## 5. Saved Investigations

### `GET /api/v1/saved`
List all saved investigations for the authenticated user.

### `POST /api/v1/saved`
Save an investigation bookmark.

### `GET /api/v1/saved/{inv_id}`
Retrieve saved investigation by ID (strictly isolated to owner; 404 for others).

### `PUT /api/v1/saved/{inv_id}`
Rename saved investigation title.

### `DELETE /api/v1/saved/{inv_id}`
Delete saved investigation (strictly isolated to owner).

---

## 6. Personalization & User Memory

### `GET /api/v1/memory`
List active analyst preferences and memory key-value pairs for the current user.

### `POST /api/v1/memory`
Store or update key-value memory context for current user.

### `DELETE /api/v1/memory/key/{key}`
Delete a specific memory key.

---

## 7. User Profile & Preferences

### `GET /api/v1/profile`
Retrieve profile, display name, team, and preferences for authenticated user.

### `PUT /api/v1/profile`
Update display name, email, team, role title, or preferences.

---

## 8. Investigation Feedback & Quality Ratings

### `POST /api/v1/feedback`
Submit satisfaction rating and review comments for an investigation query.

### `GET /api/v1/feedback/recent`
Retrieve recent feedback entries.

---

## 9. Entities & Knowledge Graph

### `GET /api/v1/entities/{entity_id}`
Retrieve detailed entity properties from Neo4j knowledge graph.

### `GET /api/v1/entities/{entity_id}/relationships`
Retrieve direct 1-hop relationships for the specified entity.

### `GET /api/v1/entities/{entity_id}/graph`
Retrieve 2-hop neighborhood subgraph formatted for D3.js or Mol* visualizers.

---

## 10. Administrator Observability & Quality (Admin Role Only)

### `GET /api/v1/admin/observability`
Comprehensive system telemetry, throughput, token consumption, and P95 latency.

### `GET /api/v1/admin/quality`
Aggregated quality metrics, analyst satisfaction ratings, and hallucination reports.

### `GET /api/v1/admin/traces`
Recent investigation execution traces with stage timings and cost breakdowns.

### `GET /api/v1/admin/alerts`
Active system anomalies, circuit breaker trips, and budget alerts.

### `GET /api/v1/admin/feedback-list`
Raw feedback logs for administrative triage.

### `GET /api/v1/admin/evaluations`
Latest automated M1–M5 benchmark evaluation results.

### `POST /api/v1/admin/evaluations/run`
Trigger on-demand benchmark evaluation suite execution.
