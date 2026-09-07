"use client";

import { useState, useEffect } from "react";

export default function SettingsPage() {
  const [health, setHealth] = useState<{
    status: string;
    llm_provider: string;
    neo4j_connected: boolean;
    cache_size: number;
    version: string;
  } | null>(null);

  useEffect(() => {
    fetch("/health")
      .then((r) => (r.ok ? r.json() : null))
      .then((data) =>
        setHealth(
          data || {
            status: "unknown",
            llm_provider: "unknown",
            neo4j_connected: false,
            cache_size: 0,
            version: "1.0.0",
          }
        )
      )
      .catch(() =>
        setHealth({
          status: "offline",
          llm_provider: "unknown",
          neo4j_connected: false,
          cache_size: 0,
          version: "1.0.0",
        })
      );
  }, []);

  return (
    <>
      <div className="page-header">
        <h2>Settings</h2>
        <p>System configuration and service status</p>
      </div>

      <div className="page-body">
        <div className="card" style={{ maxWidth: 640, marginBottom: 24 }}>
          <div className="card-title">System Status</div>
          <table>
            <tbody>
              <tr>
                <td style={{ fontWeight: 600, width: 180 }}>API Status</td>
                <td>
                  <span className={`status-dot ${health?.status === "ok" ? "online" : "offline"}`} />{" "}
                  {health?.status || "Checking…"}
                </td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>LLM Provider</td>
                <td>{health?.llm_provider || "—"}</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Neo4j Connection</td>
                <td>
                  <span className={`status-dot ${health?.neo4j_connected ? "online" : "offline"}`} />{" "}
                  {health?.neo4j_connected ? "Connected" : "Disconnected (in-memory fallback)"}
                </td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Cache Entries</td>
                <td>{health?.cache_size ?? "—"}</td>
              </tr>
              <tr>
                <td style={{ fontWeight: 600 }}>Version</td>
                <td>{health?.version || "1.0.0"}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="card" style={{ maxWidth: 640 }}>
          <div className="card-title">Configuration</div>
          <div className="alert alert-info">
            System configuration is managed via environment variables. See the{" "}
            <code>.env.example</code> file for all available settings.
          </div>
          <div style={{ marginTop: 16, fontSize: 13, color: "var(--color-text-muted)" }}>
            <p>Key configuration areas:</p>
            <ul style={{ paddingLeft: 20, marginTop: 8 }}>
              <li>LLM provider selection (mock, gemini, groq, ollama, openai, multi)</li>
              <li>Neo4j graph database connection</li>
              <li>JWT authentication secrets</li>
              <li>Rate limiting thresholds</li>
              <li>Cache TTL and size limits</li>
              <li>Query guardrails (max length, depth, timeout)</li>
            </ul>
          </div>
        </div>
      </div>
    </>
  );
}
