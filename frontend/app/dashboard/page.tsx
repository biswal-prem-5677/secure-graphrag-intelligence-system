"use client";

import { useState, useCallback } from "react";

interface QueryResult {
  answer: string;
  confidence: number | string;
  evidence?: string[];
  cited_sources?: string[];
  latency_ms?: number;
  stage_timings?: { total_pipeline_ms?: number };
  provider?: string;
  cost_usd?: number;
  failure_mode?: string;
  operational_state?: string;
  graph_entities?: string[];
  graph_data?: { nodes?: { name?: string; id?: string }[] };
}

export default function DashboardPage() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<{ q: string; a: string; ts: string }[]>([]);

  const handleQuery = useCallback(async () => {
    if (!query.trim() || loading) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const token = typeof window !== "undefined" ? (localStorage.getItem("auth_token") || localStorage.getItem("token")) : null;
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }

      const res = await fetch("/api/v1/query", {
        method: "POST",
        headers,
        body: JSON.stringify({ query: query.trim(), session_id: "demo" }),
      });

      if (!res.ok) {
        if (res.status === 401) {
          throw new Error("Authentication required. Please sign in via the 'Sign In / Register' page.");
        }
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Server error ${res.status}`);
      }

      const data = await res.json();
      setResult(data);
      setHistory((h) => [
        { q: query.trim(), a: (data.answer || "").slice(0, 120), ts: new Date().toLocaleTimeString() },
        ...h.slice(0, 19),
      ]);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [query, loading]);

  const isHighConfidence =
    typeof result?.confidence === "number"
      ? result.confidence >= 0.8
      : result?.confidence === "HIGH";
  const isMedConfidence =
    typeof result?.confidence === "number"
      ? result.confidence >= 0.5
      : result?.confidence === "MEDIUM";
  const confidenceClass = isHighConfidence
    ? "confidence-high"
    : isMedConfidence
    ? "confidence-medium"
    : "confidence-low";
  const displayConfidence =
    result?.confidence === undefined || result?.confidence === null
      ? "—"
      : typeof result.confidence === "number"
      ? `${(result.confidence * 100).toFixed(0)}%`
      : String(result.confidence);
  const displayLatency =
    result?.latency_ms ?? (result?.stage_timings?.total_pipeline_ms ? Math.round(result.stage_timings.total_pipeline_ms) : 0);
  const evidenceList =
    result?.evidence && result.evidence.length > 0
      ? result.evidence
      : result?.cited_sources && result.cited_sources.length > 0
      ? result.cited_sources
      : [];
  const entitiesList =
    result?.graph_entities && result.graph_entities.length > 0
      ? result.graph_entities
      : (result?.graph_data?.nodes || [])
          .map((n) => n.name || n.id || "")
          .filter(Boolean);

  return (
    <>
      <div className="page-header">
        <h2>Query Console</h2>
        <p>Investigate cybersecurity threats using graph-augmented reasoning</p>
      </div>

      <div className="page-body">
        {/* Query Input */}
        <div className="query-container">
          <div className="query-input-wrapper">
            <textarea
              className="query-input"
              placeholder="Ask a threat intelligence question… e.g. 'What TTPs does APT29 use for initial access?'"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  handleQuery();
                }
              }}
              rows={2}
            />
            <button
              className="btn btn-primary"
              onClick={handleQuery}
              disabled={loading || !query.trim()}
            >
              {loading ? (
                <>
                  <span className="spinner" /> Querying…
                </>
              ) : (
                "Investigate"
              )}
            </button>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="alert alert-error" style={{ marginBottom: 20 }}>
            <strong>Error:</strong> {error}
          </div>
        )}

        {/* Result */}
        {result && (
          <div className="result-panel">
            <div className="result-answer">{result.answer}</div>

            <div className="result-meta">
              <div className="result-meta-item">
                Confidence:{" "}
                <span className={`confidence-badge ${confidenceClass}`}>
                  {displayConfidence}
                </span>
              </div>
              <div className="result-meta-item">
                Latency: <span className="value">{displayLatency}ms</span>
              </div>
              <div className="result-meta-item">
                Provider: <span className="value">{result.provider || "mock"}</span>
              </div>
              <div className="result-meta-item">
                Cost: <span className="value">${result.cost_usd?.toFixed(5) ?? "0"}</span>
              </div>
              {(result.failure_mode || result.operational_state) && (
                <div className="result-meta-item">
                  State: <span className="tag tag-yellow">{result.operational_state || result.failure_mode}</span>
                </div>
              )}
            </div>

            {/* Evidence */}
            {evidenceList.length > 0 && (
              <>
                <div className="card-title" style={{ marginTop: 20 }}>
                  Evidence Sources ({evidenceList.length})
                </div>
                <ul className="evidence-list">
                  {evidenceList.map((ev, i) => (
                    <li key={i} className="evidence-item">
                      {typeof ev === "string" ? ev : JSON.stringify(ev)}
                    </li>
                  ))}
                </ul>
              </>
            )}

            {/* Graph Entities */}
            {entitiesList.length > 0 && (
              <div style={{ marginTop: 16, display: "flex", gap: 6, flexWrap: "wrap" }}>
                {entitiesList.map((e, i) => (
                  <span key={i} className="tag tag-teal">
                    {e}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Stats Cards */}
        <div className="card-grid" style={{ marginTop: 32 }}>
          <div className="card stat-card">
            <span className="stat-value">{history.length}</span>
            <span className="stat-label">Queries This Session</span>
          </div>
          <div className="card stat-card">
            <span className="stat-value">
              {result ? displayConfidence : "—"}
            </span>
            <span className="stat-label">Last Confidence</span>
          </div>
          <div className="card stat-card">
            <span className="stat-value">
              {result ? `${displayLatency}ms` : "—"}
            </span>
            <span className="stat-label">Last Latency</span>
          </div>
        </div>

        {/* Query History */}
        {history.length > 0 && (
          <div style={{ marginTop: 32 }}>
            <div className="card-title">Recent Queries</div>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Query</th>
                  <th>Answer Preview</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h, i) => (
                  <tr key={i}>
                    <td>{h.ts}</td>
                    <td>{h.q}</td>
                    <td style={{ color: "var(--color-text-muted)" }}>{h.a}…</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
