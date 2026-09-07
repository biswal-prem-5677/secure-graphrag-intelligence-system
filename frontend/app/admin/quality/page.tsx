"use client";

import { useState, useEffect } from "react";

interface EvalResult {
  metric: string;
  score: number;
  status: string;
  detail: string;
}

export default function QualityPage() {
  const [results, setResults] = useState<EvalResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    fetch("/api/v1/admin/evaluations")
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (Array.isArray(data)) setResults(data);
        else
          setResults([
            { metric: "M1 — Retrieval Precision", score: 0, status: "NOT_RUN", detail: "Run evaluation to measure" },
            { metric: "M2 — Generation Faithfulness", score: 0, status: "NOT_RUN", detail: "Run evaluation to measure" },
            { metric: "M3 — Confidence Calibration", score: 0, status: "NOT_RUN", detail: "Run evaluation to measure" },
            { metric: "M4 — Latency P95", score: 0, status: "NOT_RUN", detail: "Run evaluation to measure" },
            { metric: "M5 — Cost per Task", score: 0, status: "NOT_RUN", detail: "Run evaluation to measure" },
          ]);
      })
      .catch(() =>
        setResults([
          { metric: "M1 — Retrieval Precision", score: 0, status: "NOT_RUN", detail: "Backend offline" },
          { metric: "M2 — Generation Faithfulness", score: 0, status: "NOT_RUN", detail: "Backend offline" },
          { metric: "M3 — Confidence Calibration", score: 0, status: "NOT_RUN", detail: "Backend offline" },
          { metric: "M4 — Latency P95", score: 0, status: "NOT_RUN", detail: "Backend offline" },
          { metric: "M5 — Cost per Task", score: 0, status: "NOT_RUN", detail: "Backend offline" },
        ])
      )
      .finally(() => setLoading(false));
  }, []);

  const runEval = async () => {
    setRunning(true);
    try {
      const res = await fetch("/api/v1/admin/evaluations/run", { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data)) setResults(data);
      }
    } catch {
      /* noop */
    } finally {
      setRunning(false);
    }
  };

  const statusTag = (s: string) => {
    switch (s) {
      case "PASS":
        return <span className="tag tag-green">PASS</span>;
      case "FAIL":
        return <span className="tag tag-red">FAIL</span>;
      case "WARN":
        return <span className="tag tag-yellow">WARN</span>;
      default:
        return <span className="tag" style={{ background: "#f1f5f9", color: "#94a3b8" }}>{s}</span>;
    }
  };

  return (
    <>
      <div className="page-header">
        <h2>AI Quality Evaluation</h2>
        <p>M1–M5 metrics for retrieval, generation, confidence, latency, and cost</p>
      </div>

      <div className="page-body">
        <div style={{ marginBottom: 20, display: "flex", gap: 12 }}>
          <button className="btn btn-primary" onClick={runEval} disabled={running}>
            {running ? (
              <>
                <span className="spinner" /> Running Evaluation…
              </>
            ) : (
              "Run Evaluation Suite"
            )}
          </button>
        </div>

        {loading ? (
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span className="spinner" /> Loading evaluation results…
          </div>
        ) : (
          <div className="card">
            <table>
              <thead>
                <tr>
                  <th>Metric</th>
                  <th>Score</th>
                  <th>Status</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={i}>
                    <td style={{ fontWeight: 600 }}>{r.metric}</td>
                    <td>
                      {r.score > 0 ? (
                        <span style={{ fontWeight: 700, color: "var(--color-accent)" }}>
                          {(r.score * 100).toFixed(1)}%
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>{statusTag(r.status)}</td>
                    <td style={{ color: "var(--color-text-muted)", fontSize: 13 }}>
                      {r.detail}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="alert alert-info" style={{ marginTop: 24, maxWidth: 640 }}>
          <div>
            <strong>Note:</strong> Evaluation metrics are computed using the currently configured LLM
            provider. When using <code>LLM_PROVIDER=mock</code>, results reflect deterministic test
            outputs and are marked <em>NOT VERIFIED</em> for real-world accuracy. Switch to a live
            provider (gemini, groq, openai) for production-grade evaluation.
          </div>
        </div>
      </div>
    </>
  );
}
