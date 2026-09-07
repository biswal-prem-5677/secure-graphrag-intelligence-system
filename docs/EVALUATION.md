# AI Quality & Evaluation Framework (M1–M5)

## Evaluation Taxonomy

The evaluation framework rigorously monitors five core quality dimensions (M1–M5) across deterministic benchmarks and production inference.

---

### M1: Retrieval Precision & Recall
- **Definition**: Proportion of ground-truth threat entities and graph edges successfully retrieved during neighborhood expansion.
- **Formulation**:
  $$\text{Precision@K} = \frac{|\text{Retrieved Entities} \cap \text{Gold Entities}|}{K}$$
- **Target**: $> 85\%$ on golden test benchmark tasks.

---

### M2: Generation Faithfulness
- **Definition**: Grounding verification quantifying whether all claims in the generated response are directly supported by the retrieved graph evidence.
- **Formulation**:
  $$\text{Faithfulness} = \frac{\text{Supported Claims}}{\text{Total Asserted Claims}}$$
- **Anti-Hallucination Policy**: If retrieval finds 0 entities, the engine short-circuits to `EMPTY_RETRIEVAL` with 0% hallucination risk.

---

### M3: Confidence Calibration & Hallucination Rate
- **Definition**: Brier calibration score measuring how well predicted confidence probabilities align with factual correctness.
- **Formulation**:
  $$\text{Brier Score} = \frac{1}{N} \sum_{t=1}^N (f_t - o_t)^2$$
- **Target**: Brier score $< 0.15$.

---

### M4: Cost Per Task
- **Definition**: Financial tracking of inference cost combining input tokens, output tokens, embedding operations, and graph lookups.
- **Threshold**: Cost budget guard automatically aborts or compresses queries that would exceed the configured task expenditure limit.

---

### M5: Latency P95 & Escalation Rate
- **Definition**: 95th percentile query execution latency under continuous multi-hop querying.
- **Target**: $< 2,500\text{ ms}$ for 3-hop graph retrievals.
