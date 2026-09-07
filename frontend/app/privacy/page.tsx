export default function PrivacyPage() {
  return (
    <>
      <div className="page-header">
        <h2>Privacy Policy</h2>
        <p>Enterprise data protection and telemetry disclosure</p>
      </div>

      <div className="page-body">
        <div className="card" style={{ maxWidth: 780 }}>
          <div className="card-title">Data Privacy &amp; Retention Commitments</div>
          <div className="prose">
            <p>
              This Privacy Policy explains how the Secure GraphRAG Knowledge Intelligence System handles data,
              including threat queries, graph structures, and telemetry metrics.
            </p>
            <h3>1. Query Content &amp; Threat Indicators</h3>
            <p>
              Queries executed against the platform are evaluated only within the tenant&apos;s active session.
              No raw customer intelligence or classified threat indicators are used for training foundational LLM models.
            </p>
            <h3>2. Ephemeral In-Memory Processing</h3>
            <p>
              Graph queries and extracted context representations are held in memory only for the duration of the investigation,
              subject to configurable time-to-live (TTL) cache policies.
            </p>
            <h3>3. Telemetry &amp; Metrics</h3>
            <p>
              The system collects anonymized latency, cost, and provider reliability metrics strictly for system observability
              and M1–M5 benchmark tracking.
            </p>
          </div>
        </div>
      </div>
    </>
  );
}
