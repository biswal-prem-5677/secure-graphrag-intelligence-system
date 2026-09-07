import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root / "backend"))
sys.path.insert(0, str(root))

from evaluation.runners.run_task_eval import run_task_evaluation
from evaluation.runners.run_retrieval_eval import run_retrieval_evaluation
from evaluation.runners.run_generation_eval import run_generation_evaluation
from evaluation.runners.run_security_eval import run_security_evaluation
from evaluation.runners.run_memory_eval import run_memory_evaluation


async def run_full_evaluation() -> dict:
    start_time = datetime.now(timezone.utc).isoformat()
    print("=================================================================")
    print("  SECURE GRAPHRAG DEEP AI SYSTEM EVALUATION SUITE")
    print(f"  Execution Timestamp: {start_time}")
    print("  Provider Mode: DETERMINISTIC MOCK EVALUATION")
    print("=================================================================")

    task_metrics = await run_task_evaluation()
    retrieval_metrics = await run_retrieval_evaluation()
    gen_metrics = await run_generation_evaluation()
    sec_metrics = run_security_evaluation()
    mem_metrics = await run_memory_evaluation()

    report = {
        "metadata": {
            "timestamp": start_time,
            "provider_mode": "DETERMINISTIC MOCK EVALUATION",
            "real_llm_status": "NOT VERIFIED (Requires External API Keys: GEMINI_API_KEY / GROQ_API_KEY / OPENAI_API_KEY)",
            "graph_mode": "IN-MEMORY CANONICAL THREAT GRAPH",
        },
        "m1_m5_primary_metrics": task_metrics,
        "retrieval": retrieval_metrics,
        "generation": gen_metrics,
        "security": sec_metrics,
        "memory": mem_metrics,
        "ci_quality_gates": {
            "m1_task_completion_passed": task_metrics["m1_task_completion_rate"] >= 0.60,
            "m2_faithfulness_passed": task_metrics["m2_faithfulness"] >= 0.85,
            "m3_hallucination_passed": task_metrics["m3_hallucination_rate"] <= 0.15,
            "security_filter_passed": sec_metrics["security_filter_accuracy"] >= 0.90,
        },
    }

    out_path = root / "final_project" / "evaluation" / "eval_summary.json"
    os.makedirs(out_path.parent, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"  EVALUATION COMPLETE. Report written to {out_path}")
    return report


if __name__ == "__main__":
    asyncio.run(run_full_evaluation())
