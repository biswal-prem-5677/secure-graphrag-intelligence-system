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

## Authentication & User Management

### `POST /api/v1/auth/register`
Public user registration. Creates user, profile, and free subscription.

**Request Body:**
```json
{
  "username": "new_analyst",
  "password": "SecurePassword123!",
  "email": "analyst@example.com"
}
```

**Response (201 Created):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "username": "new_analyst",
  "role": "analyst"
}
```

### `POST /api/v1/auth/login`
Authenticate with username and password, returns JWT token.

**Request Body:**
```json
{
  "username": "analyst",
  "password": "SecureAnalyst2024!"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "username": "analyst",
  "role": "analyst"
}
```

### `GET /api/v1/auth/me`
Returns authenticated user profile (no sensitive fields).

**Response (200 OK):**
```json
{
  "id": "uuid4",
  "username": "analyst",
  "email": "analyst@example.com",
  "role": "analyst",
  "disabled": false
}
```

### `POST /api/v1/auth/logout`
Acknowledges session logout for the authenticated user.

---

## Billing & Usage

### `GET /api/v1/billing/usage`
Retrieve current daily query quota, consumption, and tier status.

