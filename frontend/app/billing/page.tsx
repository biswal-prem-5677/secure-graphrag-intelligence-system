"use client";

import { useState, useEffect } from "react";

interface UsageData {
  tier: string;
  queries_today: number;
  daily_limit: number;
  total_cost_usd: number;
  total_queries: number;
}

export default function BillingPage() {
  const [usage, setUsage] = useState<UsageData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/v1/billing/usage")
      .then((r) => (r.ok ? r.json() : null))
      .then((data) =>
        setUsage(
          data || {
            tier: "free",
            queries_today: 0,
            daily_limit: 10,
            total_cost_usd: 0,
            total_queries: 0,
          }
        )
      )
      .catch(() =>
        setUsage({
          tier: "free",
          queries_today: 0,
          daily_limit: 10,
          total_cost_usd: 0,
          total_queries: 0,
        })
      )
      .finally(() => setLoading(false));
  }, []);

  const pct = usage ? Math.min((usage.queries_today / usage.daily_limit) * 100, 100) : 0;

  return (
    <>
      <div className="page-header">
        <h2>Usage &amp; Billing</h2>
        <p>Monitor your query consumption and subscription status</p>
      </div>

      <div className="page-body">
        {loading ? (
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span className="spinner" /> Loading usage data…
          </div>
        ) : (
          <>
            {/* Current Plan */}
            <div className="card" style={{ marginBottom: 24 }}>
              <div className="card-title">Current Plan</div>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                <span className="tag tag-teal" style={{ fontSize: 14, padding: "4px 16px" }}>
                  {usage?.tier?.toUpperCase() || "FREE"}
                </span>
                <span style={{ fontSize: 14, color: "var(--color-text-muted)" }}>
                  {usage?.daily_limit} queries / day
                </span>
              </div>

              {/* Progress */}
              <div style={{ marginBottom: 8, fontSize: 13, color: "var(--color-text-secondary)" }}>
                {usage?.queries_today} / {usage?.daily_limit} queries used today
              </div>
              <div className="progress-bar">
                <div className="progress-bar-fill" style={{ width: `${pct}%` }} />
              </div>
            </div>

            {/* Stats */}
            <div className="card-grid">
              <div className="card stat-card">
                <span className="stat-value">{usage?.total_queries || 0}</span>
                <span className="stat-label">Total Queries</span>
              </div>
              <div className="card stat-card">
                <span className="stat-value">${(usage?.total_cost_usd || 0).toFixed(4)}</span>
                <span className="stat-label">Total Cost</span>
              </div>
              <div className="card stat-card">
                <span className="stat-value">{usage?.queries_today || 0}</span>
                <span className="stat-label">Today&apos;s Queries</span>
              </div>
            </div>

            {/* Upgrade CTA */}
            {usage?.tier === "free" && (
              <div className="card" style={{ marginTop: 24 }}>
                <div className="card-title">Upgrade to Pro</div>
                <p style={{ fontSize: 14, color: "var(--color-text-secondary)", marginBottom: 16 }}>
                  Get 200 queries/day, priority LLM routing, advanced evaluation metrics, and full
                  API access.
                </p>
                <button className="btn btn-primary">Upgrade Plan</button>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
