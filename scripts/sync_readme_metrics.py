#!/usr/bin/env python3
"""
Sync README.md comparative benchmark table directly from evaluation/results/baseline_comparison.json.
Ensures README metrics are always machine-generated from actual evaluation outputs.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JSON_PATH = ROOT / "evaluation" / "results" / "baseline_comparison.json"
README_PATH = ROOT / "README.md"

START_MARKER = "<!-- BENCHMARK_TABLE_START -->"
END_MARKER = "<!-- BENCHMARK_TABLE_END -->"


def sync_readme() -> None:
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    meta = data["metadata"]
    gr = data["graphrag_metrics"]
    bm = data["bm25_baseline_metrics"]
    dn = data["dense_vector_baseline_metrics"]

    gr_ci = gr["retrieval_recall_95ci"]
    bm_ci = bm["retrieval_recall_95ci"]
    dn_ci = dn["retrieval_recall_95ci"]

    block = f"""{START_MARKER}
> Auto-generated from [`evaluation/results/baseline_comparison.json`](evaluation/results/baseline_comparison.json) | Dataset: `{meta['dataset']}` ({meta['total_tasks']} held-out tasks, `sha256:{meta['dataset_sha256']}`) | Knowledge Graph: Official MITRE ATT&CK® Enterprise v{meta['attack_version']} ({meta['graph_nodes']} nodes, {meta['graph_edges']} edges)

| Canonical Metric | Secure GraphRAG | Plain BM25 Chunk RAG | Dense LSA Vector-RAG |
| :--- | :---: | :---: | :---: |
| **Retrieval Recall@K (95% CI)** | **{gr['retrieval_recall_at_k']*100:.1f}%** [{gr_ci[0]*100:.1f}–{gr_ci[1]*100:.1f}%] | {bm['retrieval_recall_at_k']*100:.1f}% [{bm_ci[0]*100:.1f}–{bm_ci[1]*100:.1f}%] | {dn['retrieval_recall_at_k']*100:.1f}% [{dn_ci[0]*100:.1f}–{dn_ci[1]*100:.1f}%] |
| **2-Hop Recall (`Actor → SW → Tech`)** | **{gr['by_category_recall'].get('two_hop_actor_sw_tech', 0)*100:.1f}%** | {bm['by_category_recall'].get('two_hop_actor_sw_tech', 0)*100:.1f}% | {dn['by_category_recall'].get('two_hop_actor_sw_tech', 0)*100:.1f}% |
| **3-Hop Recall (`Actor → SW → Tech ← Mit`)** | **{gr['by_category_recall'].get('three_hop_actor_sw_tech_mit', 0)*100:.1f}%** | {bm['by_category_recall'].get('three_hop_actor_sw_tech_mit', 0)*100:.1f}% | {dn['by_category_recall'].get('three_hop_actor_sw_tech_mit', 0)*100:.1f}% |
| **Set Intersection Recall** | **{gr['by_category_recall'].get('set_intersection', 0)*100:.1f}%** | {bm['by_category_recall'].get('set_intersection', 0)*100:.1f}% | {dn['by_category_recall'].get('set_intersection', 0)*100:.1f}% |
| **Task Completion Rate** | **{gr['task_completion_rate']*100:.1f}%** | {bm['task_completion_rate']*100:.1f}% | {dn['task_completion_rate']*100:.1f}% |
| **Generation Faithfulness (Answered)** | {gr['generation_faithfulness']:.2f} | {bm['generation_faithfulness']:.2f} | {dn['generation_faithfulness']:.2f} |
| **Refusal F1 (Ungrounded Queries)** | **{gr['refusal_f1']:.2f}** | {bm['refusal_f1']:.2f} | {dn['refusal_f1']:.2f} |
| **Latency P95** | {gr['latency_p95_ms']} ms | {bm['latency_p95_ms']} ms | {dn['latency_p95_ms']} ms |
{END_MARKER}"""

    readme = README_PATH.read_text(encoding="utf-8")
    if START_MARKER in readme and END_MARKER in readme:
        updated = re.sub(f"{re.escape(START_MARKER)}.*?{re.escape(END_MARKER)}", block, readme, flags=re.DOTALL)
    else:
        target = "Outputs are isolated per run under `evaluation/results/runs/<run_id>/` and summarized in [`evaluation/results/baseline_comparison.md`](evaluation/results/baseline_comparison.md). Detailed scoring definitions are available in [`docs/METRICS.md`](docs/METRICS.md)."
        updated = readme.replace(target, f"{target}\n\n{block}")

    README_PATH.write_text(updated, encoding="utf-8")
    print(f"Synced README.md benchmark table from {JSON_PATH}")


if __name__ == "__main__":
    sync_readme()
