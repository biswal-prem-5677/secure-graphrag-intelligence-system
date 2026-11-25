# Metrics Specification & AI Evaluation Standards

This document serves as the authoritative source of truth for all evaluation metrics, scoring definitions, and quality gate targets in the **Secure GraphRAG Knowledge Intelligence System**.

---

## 1. Metric Taxonomy

| Metric Canonical Name | Code Identifier | Target | Scope | Description |
| :--- | :--- | :---: | :---: | :--- |
| **Retrieval Recall@K** | `retrieval_recall_at_k` | $\ge 0.85$ | Retrieval | Fraction of gold-standard entities and relationship nodes recovered within the retrieved subgraph or top-$K$ text chunks. |
| **Retrieval Precision@K** | `retrieval_precision_at_k` | $\ge 0.60$ | Retrieval | Fraction of retrieved entities that belong to the validated ground-truth threat context. |
| **Path Recovery Accuracy** | `path_recovery_accuracy` | $\ge 0.75$ | Retrieval | Percentage of multi-hop causal paths ($A \to B \to C$) correctly reconstructed without missing intermediate bridge nodes. |
| **Generation Faithfulness** | `generation_faithfulness` | $\ge 0.90$ | Synthesis | Ratio of generated atomic claims that are strictly supported by the retrieved graph and cited CTI evidence records. **Calculated strictly over answered questions** (refusals excluded from denominator). |
| **Hallucination Rate** | `hallucination_rate` | $\le 0.10$ | Synthesis | Ratio of generated atomic claims containing ungrounded entities, fabricated relations, or unverified facts. Equal to $1.0 - \text{generation\_faithfulness}$ on answered queries. |
| **Refusal Precision** | `refusal_precision` | $\ge 0.95$ | Guardrail | When the system issues a refusal ("insufficient evidence"), fraction of cases where the query was genuinely ungrounded or out-of-distribution. |
| **Refusal Recall** | `refusal_recall` | $\ge 0.90$ | Guardrail | Fraction of unanswerable or adversarial queries that the system correctly refuses to answer. |
| **Refusal F1 Score** | `refusal_f1` | $\ge 0.92$ | Guardrail | Harmonic mean of Refusal Precision and Refusal Recall on unanswerable evaluation subsets. |
| **Confidence Calibration (ECE / Brier)** | `calibration_error_brier` | $< 0.15$ | Calibration | Brier score measuring the mean squared difference between predicted confidence probability $P(\text{correct})$ and binary empirical claim correctness. |
| **Latency P50** | `latency_p50_ms` | $< 250\text{ ms}$ | Performance | Median end-to-end response time across pipeline stages. |
| **Latency P95** | `latency_p95_ms` | $< 2500\text{ ms}$ | Performance | 95th percentile response time under concurrent query loads. |
| **Cost Per Query** | `cost_per_query_usd` | $< \$0.005$ | Economics | Total inference expenditure per completed query (prompt tokens + completion tokens). |

---

## 2. Refusal Independence & Non-Inflation Policy

In accordance with strict evaluation integrity:
- **Refusals are not scored as 1.0 faithfulness.**
- A refusal response triggered by empty retrieval (`EMPTY_RETRIEVAL`) or ambiguous entities (`AMBIGUOUS_ENTITY`) represents a correct guardrail interception, but does **not** count towards the factual faithfulness score of answered domain inquiries.
- Faithfulness and Hallucination are computed strictly over the set of answered inquiries ($Q_{\text{answered}}$):
  $$\text{Faithfulness} = \frac{1}{|Q_{\text{answered}}|} \sum_{q \in Q_{\text{answered}}} \frac{|\text{Supported Claims}(q)|}{|\text{Total Claims}(q)|}$$
- Refusal quality is measured independently via **Refusal Precision, Recall, and F1** over the dedicated adversarial refusal test set.

---

## 3. Grounding & Verification Methodology

Every claim $C = (s, r, o)$ in an answer is verified against the retrieved subgraph $G = (V, E)$ and cited evidence records $D$:
1. **Entity Grounding**: The subject $s$ and object $o$ must resolve to canonical node identifiers in $V$ or cited primary sources in $D$.
2. **Relational Path Grounding**: An explicit directed path or semantic relationship connecting $s$ and $o$ must exist in $E$.
3. **Temporal & Numerical Grounding**: Any specific dates, years, CVE IDs, or quantitative assertions must be corroborated by the text in $D$.
