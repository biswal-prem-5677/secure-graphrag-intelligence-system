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

    # Ensure database tables and test accounts exist for clean clone runs
    import secrets
    import uuid
    from app.db.database import init_db
    from app.models.user import User, UserRole, user_store
    from app.security.auth import hash_password

    init_db()
    for uname, urole in [("eval_user", UserRole.admin), ("analyst", UserRole.analyst)]:
        if not user_store.user_exists(uname):
            user_store.add_user(
                User(
                    id=str(uuid.uuid4()),
                    username=uname,
                    role=urole,
                    hashed_password=hash_password(secrets.token_urlsafe(16)),
                    disabled=False,
                )
            )

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

    # Isolate run results into timestamped directory and update canonical full_eval_results.json
    run_id = f"full_eval_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    run_dir = root / "evaluation" / "results" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    with open(run_dir / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    out_path = root / "evaluation" / "results" / "full_eval_results.json"
    os.makedirs(out_path.parent, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"  EVALUATION COMPLETE.")
    print(f"  Run Artifacts: {run_dir}")
    print(f"  Canonical Summary: {out_path}")
    return report


if __name__ == "__main__":
    asyncio.run(run_full_evaluation())
