"""
Benchmark for ClaimVerifier: Evaluates precision, recall, and F1 score
on a hand-labeled dataset of cyber threat intelligence claims without heuristic blacklists.
"""
import pytest
from app.evaluation.claim_verifier import claim_verifier
from app.schemas.schemas import EvidenceRecord, GraphData, GraphNode, RelationshipStep


# Hand-labeled test set: (claim, expected_supported, category)
BENCHMARK_CLAIMS = [
    # 1. Grounded True Claims (expected: True)
    ("PHANTOM DRAGON operates the DragonScale backdoor.", True, "grounded_fact"),
    ("Operation Jade Storm targeted Apex Defense Corp.", True, "grounded_fact"),
    ("CRIMSON WOLF deployed CerberusLock ransomware across healthcare targets.", True, "grounded_fact"),
    ("APT28 deployed Cobalt Strike beacons in targeted intrusions.", True, "grounded_fact"),
    ("WinRAR vulnerability CVE-2023-38831 was exploited for initial access.", True, "grounded_fact"),
    ("Volt Typhoon utilized living-off-the-land techniques using valid accounts.", True, "grounded_fact"),
    ("CERT Advisory 2022-041 confirmed intrusions targeting defense contractors.", True, "grounded_fact"),
    ("Sandworm Team deployed Industroyer against electric substations.", True, "grounded_fact"),
    ("Lazarus Group exploited Log4Shell CVE-2021-44228 against VMware Horizon servers.", True, "grounded_fact"),
    ("CISA Advisory AA23-347A confirmed exploitation of CVE-2023-23397.", True, "grounded_fact"),

    # 2. Refusal / Absence Statements (expected: True)
    ("Insufficient evidence in the knowledge base to establish this relationship.", True, "truthful_refusal"),
    ("No verified threat intelligence records found for this entity.", True, "truthful_refusal"),
    ("Could not establish a verified connection in available evidence.", True, "truthful_refusal"),

    # 3. Ungrounded Entity Hallucinations (expected: False)
    ("PHANTOM DRAGON deployed Stuxnet to compromise uranium centrifuges.", False, "ungrounded_entity"),
    ("CRIMSON WOLF utilized alien_cyber_botnet to disrupt satellite navigation.", False, "ungrounded_entity"),
    ("Operation Jade Storm compromised SolarWinds Orion build servers.", False, "ungrounded_entity"),
    ("Sandworm Team weaponized EternalBlue against US hospitals in 2029.", False, "ungrounded_entity"),
    ("Volt Typhoon deployed non_existent_stealer to exfiltrate banking tokens.", False, "ungrounded_entity"),
    ("Lazarus Group breached MegaCorp999 utilizing CVE-2099-99999.", False, "ungrounded_entity"),
    ("APT28 deployed OlympicDestroyer against Tokyo Olympic servers.", False, "ungrounded_entity"),

    # 4. Disconnected / Fabricated Relationships (expected: False)
    # Real entities, but the relationship is false or unverified in the graph
    ("PHANTOM DRAGON authored and deployed Industroyer against the Ukrainian power grid.", False, "unsupported_relation"),
    ("Volt Typhoon deployed CerberusLock against healthcare organizations.", False, "unsupported_relation"),
    ("CRIMSON WOLF weaponized CVE-2023-38831 WinRAR zero-day.", False, "unsupported_relation"),
]


@pytest.fixture
def test_graph_context():
    nodes = [
        GraphNode(id="act-001", name="PHANTOM DRAGON", label="ThreatActor"),
        GraphNode(id="act-002", name="CRIMSON WOLF", label="ThreatActor"),
        GraphNode(id="act-003", name="Sandworm Team", label="ThreatActor"),
        GraphNode(id="act-004", name="Volt Typhoon", label="ThreatActor"),
        GraphNode(id="act-005", name="Lazarus Group", label="ThreatActor"),
        GraphNode(id="act-006", name="APT28", label="ThreatActor"),
        GraphNode(id="cmp-001", name="Operation Jade Storm", label="Campaign"),
        GraphNode(id="mal-001", name="DragonScale", label="Malware"),
        GraphNode(id="mal-002", name="Cobalt Strike", label="Malware"),
        GraphNode(id="mal-003", name="CerberusLock", label="Malware"),
        GraphNode(id="mal-004", name="Industroyer", label="Malware"),
        GraphNode(id="vuln-001", name="WinRAR CVE-2023-38831", label="Vulnerability", properties={"software": "WinRAR"}),
        GraphNode(id="vuln-002", name="Log4Shell CVE-2021-44228", label="Vulnerability", properties={"aliases": ["Log4Shell"]}),
        GraphNode(id="vuln-003", name="CVE-2023-23397", label="Vulnerability", properties={"software": "Microsoft Outlook"}),
        GraphNode(id="tgt-001", name="Apex Defense Corp", label="Target"),
        GraphNode(id="tgt-002", name="Healthcare", label="Target"),
        GraphNode(id="tgt-003", name="Electric Substations", label="Target"),
    ]
    paths = [
        RelationshipStep(source="PHANTOM DRAGON", relation="USES", target="DragonScale"),
        RelationshipStep(source="PHANTOM DRAGON", relation="CONDUCTS", target="Operation Jade Storm"),
        RelationshipStep(source="Operation Jade Storm", relation="TARGETS", target="Apex Defense Corp"),
        RelationshipStep(source="CRIMSON WOLF", relation="USES", target="CerberusLock"),
        RelationshipStep(source="CRIMSON WOLF", relation="TARGETS", target="Healthcare"),
        RelationshipStep(source="APT28", relation="USES", target="Cobalt Strike"),
        RelationshipStep(source="APT28", relation="EXPLOITS", target="CVE-2023-38831"),
        RelationshipStep(source="Sandworm Team", relation="USES", target="Industroyer"),
        RelationshipStep(source="Sandworm Team", relation="TARGETS", target="Electric Substations"),
        RelationshipStep(source="Lazarus Group", relation="EXPLOITS", target="CVE-2021-44228"),
    ]
    evidence = [
        EvidenceRecord(
            source_id="CERT-2022-041",
            title="CERT Advisory 2022-041",
            source_type="Advisory",
            confidence=0.95,
            summary="Intrusion confirmed targeting defense contractors.",
        ),
        EvidenceRecord(
            source_id="CISA-AA23-347A",
            title="CISA Advisory AA23-347A",
            source_type="Advisory",
            confidence=0.98,
            summary="CISA confirms exploitation of CVE-2023-23397 and Log4Shell on VMware Horizon servers.",
        ),
        EvidenceRecord(
            source_id="CISA-VOLT-TYPHOON",
            title="CISA Advisory Volt Typhoon",
            source_type="Advisory",
            confidence=0.99,
            summary="Volt Typhoon utilized living-off-the-land techniques using valid accounts.",
        ),
    ]
    return GraphData(nodes=nodes, edges=[]), paths, evidence


def test_claim_verifier_precision_recall_f1(test_graph_context):
    graph, paths, evidence = test_graph_context
    index = claim_verifier._build_grounding_index(graph, paths, evidence)

    tp, fp, tn, fn = 0, 0, 0, 0

    for claim, expected_supported, category in BENCHMARK_CLAIMS:
        is_supported, reason = claim_verifier.verify_claim(claim, index)

        if expected_supported and is_supported:
            tp += 1
        elif not expected_supported and is_supported:
            fp += 1
            print(f"FALSE POSITIVE: '{claim}' (Category: {category}, Reason: {reason})")
        elif not expected_supported and not is_supported:
            tn += 1
        else:
            fn += 1
            print(f"FALSE NEGATIVE: '{claim}' (Category: {category}, Reason: {reason})")

    total = len(BENCHMARK_CLAIMS)
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"\n--- CLAIM VERIFIER BENCHMARK RESULTS ---")
    print(f"Total Hand-labeled Claims: {total}")
    print(f"True Positives: {tp} | True Negatives: {tn}")
    print(f"False Positives: {fp} | False Negatives: {fn}")
    print(f"Accuracy : {accuracy * 100:.1f}%")
    print(f"Precision: {precision * 100:.1f}%")
    print(f"Recall   : {recall * 100:.1f}%")
    print(f"F1 Score : {f1:.3f}")

    assert accuracy >= 0.90, f"Claim verifier accuracy {accuracy:.2f} is below target 0.90"
    assert precision >= 0.85, f"Claim verifier precision {precision:.2f} is below target 0.85"
    assert recall >= 0.85, f"Claim verifier recall {recall:.2f} is below target 0.85"
    assert f1 >= 0.85, f"Claim verifier F1 score {f1:.3f} is below target 0.85"
