export default function AboutPage() {
  return (
    <>
      <div className="page-header">
        <h2>About Secure GraphRAG</h2>
        <p>Grounded cyber threat intelligence through graph retrieval-augmented generation</p>
      </div>

      <div className="page-body">
        <div className="card" style={{ maxWidth: 780 }}>
          <div className="card-title">Mission &amp; Capabilities</div>
          <div className="prose">
            <p>
              The <strong>Secure GraphRAG Knowledge Intelligence System</strong> bridges complex graph databases
              and state-of-the-art language models to empower SOC analysts, threat hunters, and security researchers.
            </p>
            <h3>Core Capabilities</h3>
            <ul>
              <li><strong>Hybrid Knowledge Engine:</strong> High-speed Cypher traversal in Neo4j coupled with in-memory semantic fallback.</li>
              <li><strong>Multi-Provider LLM Orchestration:</strong> Resilient routing across Gemini, Groq, Ollama, and OpenAI with circuit breaker failover.</li>
              <li><strong>M1–M5 Evaluation Metrics:</strong> Rigorous automated testing for precision, faithfulness, calibration, latency, and operational cost.</li>
              <li><strong>Explainable Confidence Scoring:</strong> Multi-factor scoring calculated from graph path density, lexical relevance, and semantic consistency.</li>
              <li><strong>Enterprise Defense Guardrails:</strong> Automatic detection and neutralization of prompt injections, token overflows, and sensitive data leakage.</li>
            </ul>
          </div>
        </div>
      </div>
    </>
  );
}
