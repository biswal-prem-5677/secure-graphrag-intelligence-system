# REST API Reference

All endpoints are served under `/api/v1` with JSON request and response payloads.

---

## Query Endpoints

### `POST /api/v1/query`
Execute a GraphRAG investigation query.

**Request Body:**
```json
{
  "query": "What attack patterns does APT29 utilize for initial compromise?",
  "session_id": "session-1234",
  "max_depth": 3,
  "confidence_threshold": 0.6
}
```

**Response Body:**
```json
{
  "query_id": "uuid4",
  "answer": "APT29 leverages Spearphishing Attachment (T1566.001) and Valid Accounts (T1078)...",
  "confidence": 0.88,
  "evidence": [
    "ThreatActor(APT29) -[USES]-> AttackPattern(T1566.001)",
    "AttackPattern(T1566.001) -[PART_OF]-> Campaign(SolarWinds Supply Chain)"
  ],
  "graph_entities": ["APT29", "T1566.001", "T1078"],
  "latency_ms": 342,
  "provider": "gemini",
  "cost_usd": 0.00042,
  "operational_state": "TASK_COMPLETED"
}
```

---

## Health & Observability

### `GET /health`
Liveness probe.
```json
{
  "status": "ok",
  "version": "1.0.0",
  "llm_provider": "gemini",
  "neo4j_connected": true
}
```

### `GET /metrics`
Prometheus and telemetry runtime statistics.
```json
{
  "total_requests": 1420,
  "avg_latency_ms": 284,
  "error_rate": 0.002,
  "cache": {
    "hits": 384,
    "misses": 1036,
    "size": 384
  }
}
```

---

## Authentication & Billing

### `POST /api/v1/auth/token`
Obtain JWT bearer access token.

### `GET /api/v1/billing/usage`
Retrieve current daily query quota, consumption, and tier status.
