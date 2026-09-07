export default function TermsPage() {
  return (
    <>
      <div className="page-header">
        <h2>Terms of Service</h2>
        <p>Operational conditions, acceptable use, and license boundaries</p>
      </div>

      <div className="page-body">
        <div className="card" style={{ maxWidth: 780 }}>
          <div className="card-title">Terms &amp; Operational Policies</div>
          <div className="prose">
            <p>
              By deploying or interacting with the Secure GraphRAG Knowledge Intelligence System, you agree to
              the following operational guidelines:
            </p>
            <h3>1. Authorized Threat Research &amp; Defense</h3>
            <p>
              This system is engineered solely for defensive cybersecurity intelligence, adversary TTP analysis,
              and authorized threat hunting. Use of the system for automated offensive weaponization is prohibited.
            </p>
            <h3>2. Open Source Licensing</h3>
            <p>
              The core software is provided under the terms of the MIT License. Third-party dependencies,
              ontologies, and datasets maintain their respective upstream licenses as detailed in our software provenance documentation.
            </p>
            <h3>3. Reliability and Operational Disclaimer</h3>
            <p>
              While the system implements strict claim-level verification and confidence scoring, intelligence
              outputs should always be validated by qualified security analysts prior to deploying critical perimeter blocks.
            </p>
          </div>
        </div>
      </div>
    </>
  );
}
