"use client";

import { useState, useEffect } from "react";

interface Metrics {
  total_requests: number;
  avg_latency_ms: number;
  error_rate: number;
  cache: {
    hits: number;
    misses: number;
    size: number;
  };
  providers: Record<string, { calls: number; avg_ms: number; errors: number }>;
  uptime_seconds: number;
}

export default function ObservabilityPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState("");

  const fetchMetrics = () => {
    setLoading(true);
    fetch("/metrics")
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        setMetrics(
          data || {
            total_requests: 0,
            avg_latency_ms: 0,
            error_rate: 0,
            cache: { hits: 0, misses: 0, size: 0 },
            providers: {},
            uptime_seconds: 0,
          }
        );
        setLastRefresh(new Date().toLocaleTimeString());
      })
      .catch(() =>
        setMetrics({
          total_requests: 0,
          avg_latency_ms: 0,
          error_rate: 0,
          cache: { hits: 0, misses: 0, size: 0 },
          providers: {},
          uptime_seconds: 0,
        })
      )
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchMetrics();
  }, []);

  const formatUptime = (s: number) => {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    return `${h}h ${m}m`;
  };

  return (
    <>
      <div className="page-header">
        <h2>Observability</h2>
        <p>
          Real-time system metrics and performance monitoring{" "}
          {lastRefresh && (
            <span style={{ color: "var(--color-text-muted)" }}>
              · Last refresh: {lastRefresh}
            </span>
          )}
        </p>
      </div>

      <div className="page-body">
        <div style={{ marginBottom: 20 }}>
          <button className="btn btn-secondary" onClick={fetchMetrics} disabled={loading}>
            {loading ? <span className="spinner" /> : "↻"} Refresh Metrics
          </button>
        </div>

        {/* Stats Grid */}
        <div className="card-grid">
          <div className="card stat-card">
            <span className="stat-value">{metrics?.total_requests || 0}</span>
            <span className="stat-label">Total Requests</span>
          </div>
          <div className="card stat-card">
            <span className="stat-value">{metrics?.avg_latency_ms?.toFixed(0) || 0}ms</span>
            <span className="stat-label">Avg Latency</span>
          </div>
          <div className="card stat-card">
            <span className="stat-value">
              {((metrics?.error_rate || 0) * 100).toFixed(1)}%
            </span>
            <span className="stat-label">Error Rate</span>
          </div>
          <div className="card stat-card">
            <span className="stat-value">
              {metrics?.uptime_seconds ? formatUptime(metrics.uptime_seconds) : "—"}
            </span>
            <span className="stat-label">Uptime</span>
          </div>
        </div>

        {/* Cache Stats */}
        <div className="card" style={{ marginTop: 24 }}>
          <div className="card-title">Cache Performance</div>
          <table>
            <thead>
              <tr>
                <th>Metric</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Cache Hits</td>
                <td>{metrics?.cache?.hits || 0}</td>
              </tr>
              <tr>
                <td>Cache Misses</td>
                <td>{metrics?.cache?.misses || 0}</td>
              </tr>
              <tr>
                <td>Cache Size</td>
                <td>{metrics?.cache?.size || 0} entries</td>
              </tr>
              <tr>
                <td>Hit Ratio</td>
                <td>
                  {metrics?.cache && (metrics.cache.hits + metrics.cache.misses) > 0
                    ? (
                        (metrics.cache.hits / (metrics.cache.hits + metrics.cache.misses)) *
                        100
                      ).toFixed(1) + "%"
                    : "—"}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Provider Stats */}
        {metrics?.providers && Object.keys(metrics.providers).length > 0 && (
          <div className="card" style={{ marginTop: 24 }}>
            <div className="card-title">LLM Provider Performance</div>
            <table>
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>Calls</th>
                  <th>Avg Latency</th>
                  <th>Errors</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(metrics.providers).map(([name, data]) => (
                  <tr key={name}>
                    <td style={{ fontWeight: 600 }}>{name}</td>
                    <td>{data.calls}</td>
                    <td>{data.avg_ms?.toFixed(0)}ms</td>
                    <td>
                      {data.errors > 0 ? (
                        <span className="tag tag-red">{data.errors}</span>
                      ) : (
                        <span className="tag tag-green">0</span>
                      )}
                    </td>
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
