export default function TrustPage() {
  return (
    <>
      <div className="page-header">
        <h2>Trust &amp; Security Architecture</h2>
        <p>Security guardrails, LLM hallucination prevention, and data provenance</p>
      </div>

      <div className="page-body">
        <div className="card" style={{ maxWidth: 780, marginBottom: 24 }}>
          <div className="card-title">Deterministic Grounding &amp; Anti-Hallucination Guarantees</div>
          <div className="prose">
            <p>
              The Secure GraphRAG platform is architected specifically to eliminate hallucinated intelligence
              and ensure high-assurance cybersecurity analytics.
            </p>
            <h4>1. Empty Retrieval Short-Circuit</h4>
            <p>
              If multi-hop graph traversal finds zero relevant entities, attack vectors, or threat intelligence paths,
              the query service short-circuits immediately with status <code>EMPTY_RETRIEVAL</code> without calling the LLM.
              This guarantees the model will never fabricate indicators of compromise (IOCs) or fictitious CVEs.
            </p>
            <h4>2. Strict Claim-Level Verification</h4>
            <p>
              Every generated assertion is cross-checked against retrieved subgraphs. Extracted claims without explicit
              source grounding are penalized in the confidence metric and flagged in telemetry.
            </p>
            <h4>3. Multi-Hop Graph Traversal with Neo4j</h4>
            <p>
              Threat relationships (actors, malware, campaigns, infrastructure, vulnerabilities) are mapped across canonical
              cybersecurity schemas (MITRE ATT&amp;CK, STIX 2.1, CAPEC) providing strict causal provenance.
            </p>
            <h4>4. Multi-Tiered Failure Recovery Taxonomy</h4>
            <p>
              Failures are classified into 21 canonical operational states (including <code>LLM_TIMEOUT</code>, <code>LLM_RATE_LIMIT</code>,
              <code>COST_BUDGET_EXCEEDED</code>, <code>LOW_CONFIDENCE_ANSWER</code>) with automated fallback and human escalation triggers.
            </p>
          </div>
        </div>

        <div className="card" style={{ maxWidth: 780 }}>
          <div className="card-title">Data Privacy &amp; Credential Isolation</div>
          <div className="prose">
            <p>
              All queries and session states are isolated per-tenant. API keys for LLM providers (Gemini, Groq, Ollama, OpenAI)
              are encrypted in memory and never exposed in client bundles or logged payloads.
            </p>
          </div>
        </div>
      </div>
    </>
  );
}
