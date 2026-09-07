"use client";

import { useState, useCallback } from "react";

interface QueryResult {
  answer: string;
  confidence: number;
  evidence: string[];
  latency_ms: number;
  provider: string;
  cost_usd: number;
  failure_mode?: string;
  graph_entities?: string[];
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
      const res = await fetch("/api/v1/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: query.trim(), session_id: "demo" }),
      });

      if (!res.ok) {
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

  const confidenceClass =
    result && result.confidence >= 0.8
      ? "confidence-high"
      : result && result.confidence >= 0.5
      ? "confidence-medium"
      : "confidence-low";

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
                  {(result.confidence * 100).toFixed(0)}%
                </span>
              </div>
              <div className="result-meta-item">
                Latency: <span className="value">{result.latency_ms}ms</span>
              </div>
              <div className="result-meta-item">
                Provider: <span className="value">{result.provider}</span>
              </div>
              <div className="result-meta-item">
                Cost: <span className="value">${result.cost_usd?.toFixed(5) ?? "0"}</span>
              </div>
              {result.failure_mode && (
                <div className="result-meta-item">
                  Failure Mode: <span className="tag tag-yellow">{result.failure_mode}</span>
                </div>
              )}
            </div>

            {/* Evidence */}
            {result.evidence && result.evidence.length > 0 && (
              <>
                <div className="card-title" style={{ marginTop: 20 }}>
                  Evidence Sources ({result.evidence.length})
                </div>
                <ul className="evidence-list">
                  {result.evidence.map((ev, i) => (
                    <li key={i} className="evidence-item">
                      {ev}
                    </li>
                  ))}
                </ul>
              </>
            )}

            {/* Graph Entities */}
            {result.graph_entities && result.graph_entities.length > 0 && (
              <div style={{ marginTop: 16, display: "flex", gap: 6, flexWrap: "wrap" }}>
                {result.graph_entities.map((e, i) => (
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
              {result ? `${(result.confidence * 100).toFixed(0)}%` : "—"}
            </span>
            <span className="stat-label">Last Confidence</span>
          </div>
          <div className="card stat-card">
            <span className="stat-value">
              {result ? `${result.latency_ms}ms` : "—"}
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
