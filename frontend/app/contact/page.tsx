export default function ContactPage() {
  return (
    <>
      <div className="page-header">
        <h2>Contact &amp; Support</h2>
        <p>Get in touch with the Secure GraphRAG intelligence and engineering team</p>
      </div>

      <div className="page-body">
        <div className="card" style={{ maxWidth: 640 }}>
          <div className="card-title">Engineering &amp; Security Inquiries</div>
          <p style={{ color: "var(--color-text-secondary)", marginBottom: 16 }}>
            For enterprise deployments, custom threat ontology integrations, or security vulnerability disclosures:
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div>
              <strong>Security Inquiries:</strong>{" "}
              <a href="mailto:security@graphrag-intelligence.internal" style={{ color: "var(--color-accent)" }}>
                security@graphrag-intelligence.internal
              </a>
            </div>
            <div>
              <strong>Technical Support:</strong>{" "}
              <a href="mailto:support@graphrag-intelligence.internal" style={{ color: "var(--color-accent)" }}>
                support@graphrag-intelligence.internal
              </a>
            </div>
            <div>
              <strong>Repository:</strong>{" "}
              <a
                href="https://github.com/biswal-prem-5677/secure-graphrag-intelligence-system"
                target="_blank"
                rel="noreferrer"
                style={{ color: "var(--color-accent)" }}
              >
                github.com/biswal-prem-5677/secure-graphrag-intelligence-system
              </a>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
