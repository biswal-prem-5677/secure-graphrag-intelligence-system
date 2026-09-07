import asyncio
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root / "final_project" / "backend"))
sys.path.insert(0, str(root / "final_project"))

from app.retrieval.graph_retriever import graph_retriever
from app.retrieval.query_analyzer import query_analyzer
from evaluation.metrics.retrieval_metrics import compute_mrr, compute_precision_recall_f1


async def run_retrieval_evaluation() -> dict:
    data_file = root / "final_project" / "evaluation" / "datasets" / "retrieval_eval.jsonl"
    if not data_file.exists():
        data_file = Path("evaluation/datasets/retrieval_eval.jsonl")

    cases = []
    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                cases.append(json.loads(line))

    print(f"\n=======================================================")
    print(f"  RUNNING RETRIEVAL EVALUATION ({len(cases)} test cases)")
    print(f"=======================================================")

    mrrs = []
    for c in cases:
        analysis = query_analyzer.analyze(c["query"])
        res = await graph_retriever.retrieve_subgraph(analysis.entities or [c["query"]], max_depth=2)
        retrieved_names = [n.name for n in res.graph_data.nodes]
        p, r, f1 = compute_precision_recall_f1(retrieved_names, c["target_entities"], k=5)
        mrr = compute_mrr(retrieved_names, c["target_entities"])
        mrrs.append(mrr)
        print(f"  [{c['id']}] P@5: {p:.2f} | R: {r:.2f} | MRR: {mrr:.2f}")

    avg_mrr = round(sum(mrrs) / len(mrrs), 2) if mrrs else 1.0
    print(f"  Mean MRR: {avg_mrr:.2f}")
    print(f"=======================================================\n")
    return {"mean_mrr": avg_mrr}


if __name__ == "__main__":
    asyncio.run(run_retrieval_evaluation())
