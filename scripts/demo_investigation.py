#!/usr/bin/env python3
"""
Secure GraphRAG Knowledge Intelligence System - Live Investigation Demo
Demonstrates multi-hop graph traversal, STIX 2.1 threat intelligence synthesis,
and anti-hallucination verification with real MITRE ATT&CK entities.
"""
import asyncio
import os
import sys
from pathlib import Path

# Ensure root and backend directory are on PYTHONPATH
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
os.chdir(ROOT)

from app.schemas.schemas import QueryRequest, TaskCompletionStatus
from app.services.query_service import QueryService
from app.db.database import init_db
from app.security.auth import seed_default_users

BOLD = "\033[1m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"
RESET = "\033[0m"


def print_banner():
    from app.retrieval.graph_retriever import graph_retriever
    d = graph_retriever._get_offline_data()
    n_cnt = len(d.get("nodes", []))
    e_cnt = len(d.get("edges", []))
    ev_cnt = len(d.get("evidence", []))
    ver = d.get("metadata", {}).get("version", "20.1")
    print(f"""
{CYAN}========================================================================{RESET}
{BOLD}{GREEN}  SECURE GRAPHRAG KNOWLEDGE INTELLIGENCE SYSTEM{RESET}
{BOLD}  Live Threat Intelligence Investigation & Multi-Hop Traversal Demo{RESET}
{CYAN}========================================================================{RESET}
  Knowledge Base : Official MITRE ATT&CK Enterprise v{ver} ({n_cnt} nodes, {e_cnt} edges, {ev_cnt} citations)
  Defense Engine : Directed Multi-Hop Traversal, Provenance Citations & Claim Verification
""")


def render_response(resp):
    print(f"\n{BOLD}Query ID:{RESET} {resp.query_id}")
    print(f"{BOLD}Status:{RESET}   {GREEN if resp.task_status == TaskCompletionStatus.TASK_COMPLETED else RED}{resp.task_status.value}{RESET}")
    print(f"{BOLD}Confidence:{RESET} {CYAN}{resp.confidence.value}{RESET} ({resp.confidence_explanation})")
    print(f"{BOLD}Faithfulness Score:{RESET} {YELLOW}{resp.faithfulness_score:.2f}{RESET}")

    print(f"\n{BOLD}{CYAN}--- Synthesized Intelligence Answer ---{RESET}")
    print(f"{resp.answer}\n")

    if resp.relationship_paths:
        print(f"{BOLD}{MAGENTA}--- Traversed Multi-Hop Relationship Paths ({len(resp.relationship_paths)}) ---{RESET}")
        for p in resp.relationship_paths[:8]:
            print(f"  • {BOLD}{p.source}{RESET} --[{CYAN}{p.relation}{RESET}]--> {BOLD}{p.target}{RESET}")
        if len(resp.relationship_paths) > 8:
            print(f"  ... and {len(resp.relationship_paths) - 8} more relationship paths")

    if resp.graph_data.nodes:
        print(f"\n{BOLD}{GREEN}--- Discovered Graph Entities ({len(resp.graph_data.nodes)}) ---{RESET}")
        by_label = {}
        for n in resp.graph_data.nodes:
            by_label.setdefault(n.label, []).append(f"{n.name} ({n.id})")
        for label, nodes in by_label.items():
            print(f"  {BOLD}{label}:{RESET} {', '.join(nodes[:5])}{' ...' if len(nodes) > 5 else ''}")

    if resp.evidence_records:
        print(f"\n{BOLD}{YELLOW}--- Corroborating CTI Evidence Records ({len(resp.evidence_records)}) ---{RESET}")
        for ev in resp.evidence_records[:3]:
            print(f"  [{ev.source_id}] {ev.title} (Confidence: {ev.confidence*100:.0f}%)")
            print(f"    Summary: {ev.summary[:140]}...")

    if resp.stage_timings:
        print(f"\n{BOLD}--- Stage Timings ---{RESET}")
        st = resp.stage_timings
        print(f"  Validation: {st.validation_ms:.1f}ms | Traversal: {st.graph_retrieval_ms:.1f}ms | Total Pipeline: {st.total_pipeline_ms:.1f}ms")
    print(f"{CYAN}{'=' * 72}{RESET}\n")


async def run_demo():
    import secrets
    import uuid
    from app.models.user import User, UserRole, user_store
    from app.security.auth import hash_password

    print_banner()
    init_db()
    if not user_store.user_exists("eval_user"):
        user_store.add_user(
            User(
                id=str(uuid.uuid4()),
                username="eval_user",
                role=UserRole.admin,
                hashed_password=hash_password(secrets.token_urlsafe(16)),
                disabled=False,
            )
        )
    query_service = QueryService()

    demo_cases = [
        {
            "title": "CASE 1: Multi-Hop APT28 Infrastructure & Toolchain Analysis",
            "query": "What post-exploitation framework and process injection technique does APT28 utilize?",
            "hops": 3,
        },
        {
            "title": "CASE 2: Cross-Campaign Lateral Movement & Credential Dumping",
            "query": "What credential dumping tool does Lazarus Group employ for lateral movement and what mitigates it?",
            "hops": 3,
        },
        {
            "title": "CASE 3: Anti-Hallucination Guardrail Intercepting Ungrounded Adversarial Query",
            "query": "Which alien botnet did APT29 deploy in 2029?",
            "hops": 2,
        },
    ]

    for case in demo_cases:
        print(f"\n{BOLD}{YELLOW}>>> {case['title']}{RESET}")
        print(f"{BOLD}Analyst Question:{RESET} \"{case['query']}\"")
        req = QueryRequest(query=case["query"], max_hops=case["hops"])
        resp = await query_service.execute_query(req, user_id="eval_user", user_role="admin")
        render_response(resp)
        await asyncio.sleep(0.5)

    if "--interactive" in sys.argv:
        print(f"\n{BOLD}{GREEN}Entering Interactive Investigation Mode... (Type 'exit' to quit){RESET}\n")
        while True:
            try:
                user_q = input(f"{BOLD}Investigate Query>{RESET} ").strip()
                if not user_q or user_q.lower() in ("exit", "quit"):
                    break
                req = QueryRequest(query=user_q, max_hops=3)
                resp = await query_service.execute_query(req, user_id="eval_user", user_role="admin")
                render_response(resp)
            except (KeyboardInterrupt, EOFError):
                break
        print(f"\n{GREEN}Exited interactive mode.{RESET}")


if __name__ == "__main__":
    asyncio.run(run_demo())
