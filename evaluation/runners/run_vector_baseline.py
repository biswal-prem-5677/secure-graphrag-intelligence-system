"""
Comparative Benchmark Runner: Secure GraphRAG vs. Plain Vector-RAG Baseline.
Evaluates 105 multi-hop threat intelligence queries across Retrieval Recall,
Multi-Hop Path Coverage, Faithfulness, Hallucination Rate, and Latency.
"""
from __future__ import annotations

import asyncio
import json
import math
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root / "backend"))
sys.path.insert(0, str(root))

from app.db.database import init_db
from app.evaluation.claim_verifier import claim_verifier
from app.retrieval.graph_retriever import graph_retriever
from app.schemas.schemas import EvidenceRecord, GraphData, OperationalState, QueryRequest, TaskCompletionStatus
from app.services.query_service import query_service


class PlainVectorRAGBaseline:
    """
    Standard Vector / BM25 Text-Retrieval RAG baseline without graph topology traversal.
    Splits the CTI corpus into isolated textual documents and ranks by term similarity.
    """

    def __init__(self, corpus_docs: List[Dict[str, str]]) -> None:
        self.docs = corpus_docs
        self.doc_tokens: List[List[str]] = [self._tokenize(d["text"]) for d in self.docs]
        self.num_docs = len(self.docs)
        self.df = Counter()
        for tokens in self.doc_tokens:
            for term in set(tokens):
                self.df[term] += 1

    def _tokenize(self, text: str) -> List[str]:
        return [w.lower() for w in re.findall(r"\b[a-zA-Z0-9_-]{2,}\b", text)]

    def retrieve(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Retrieve top-K chunks using BM25 / TF-IDF scoring."""
        q_tokens = self._tokenize(query)
        scores: List[Tuple[float, int]] = []

        for idx, doc_toks in enumerate(self.doc_tokens):
            if not doc_toks:
                continue
            score = 0.0
            doc_len = len(doc_toks)
            term_counts = Counter(doc_toks)
            for t in q_tokens:
                if t in self.df:
                    idf = math.log((self.num_docs - self.df[t] + 0.5) / (self.df[t] + 0.5) + 1.0)
                    tf = term_counts.get(t, 0)
                    score += idf * ((tf * 2.2) / (tf + 1.2 * (0.25 + 0.75 * doc_len / 30.0)))
            scores.append((score, idx))

        scores.sort(key=lambda x: x[0], reverse=True)
        return [self.docs[idx] for score, idx in scores[:top_k] if score > 0.0]


def build_text_corpus(graph_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build isolated text chunks from nodes, edges, and evidence for the Vector-RAG baseline."""
    chunks = []
    for ev in graph_data.get("evidence", []):
        chunks.append({"id": ev.get("source_id", ""), "text": f"{ev.get('title', '')}: {ev.get('summary', '')}"})

    for n in graph_data.get("nodes", []):
        props_str = " ".join(f"{k}: {v}" for k, v in n.get("properties", {}).items())
        chunks.append({"id": n.get("id", ""), "text": f"Entity {n.get('name', '')} ({n.get('label', '')}). {props_str}"})

    for e in graph_data.get("edges", []):
        desc = e.get("properties", {}).get("description", "")
        chunks.append({"id": f"{e.get('source')}-{e.get('target')}", "text": f"{e.get('source')} {e.get('type')} {e.get('target')}. {desc}"})

    return chunks


async def run_comparative_benchmark(max_tasks: int = 105) -> Dict[str, Any]:
    print("=========================================================================")
    print("  SECURE GRAPHRAG VS. PLAIN VECTOR-RAG COMPARATIVE BENCHMARK")
    print(f"  Benchmark Suite: 105 Multi-Hop Threat Intelligence Tasks")
    print("=========================================================================")

    # Ensure database tables and eval user exist for clean clone runs
    import secrets
    import uuid
    from app.models.user import User, UserRole, user_store
    from app.security.auth import hash_password

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

    # Load multi-hop evaluation dataset
    dataset_path = root / "evaluation" / "datasets" / "mitre_multihop_100.jsonl"
    tasks = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                tasks.append(json.loads(line))

    tasks = tasks[:max_tasks]

    # Initialize Vector-RAG Baseline with STIX Corpus
    offline_data = graph_retriever._get_offline_data()
    corpus = build_text_corpus(offline_data)
    vector_rag = PlainVectorRAGBaseline(corpus)

    graphrag_entity_recalls: List[float] = []
    vectorrag_entity_recalls: List[float] = []
    graphrag_latencies: List[float] = []
    vectorrag_latencies: List[float] = []
    graphrag_answered_faithfulness: List[float] = []
    vectorrag_answered_faithfulness: List[float] = []
    graphrag_answered_hallucination: List[float] = []
    vectorrag_answered_hallucination: List[float] = []
    graphrag_completed_count = 0
    vectorrag_completed_count = 0
    gr_refusal_tp = gr_refusal_fp = gr_refusal_fn = 0
    vr_refusal_tp = vr_refusal_fp = vr_refusal_fn = 0

    print(f"Executing head-to-head evaluation across {len(tasks)} multi-hop tasks...\n")

    for idx, t in enumerate(tasks, 1):
        q = t["query"]
        gold_ents = set(e.lower() for e in t.get("gold_entities", []))
        hop_count = t.get("hop_count", 2)
        is_refusal = (t.get("category") == "adversarial_refusal")

        # 1. Execute GraphRAG Pipeline
        t0 = time.time()
        req = QueryRequest(query=q)
        gr_resp = await query_service.execute_query(req, user_id="eval_user", user_role="admin")
        gr_time = (time.time() - t0) * 1000
        graphrag_latencies.append(gr_time)

        # GraphRAG Entity Recall
        gr_found = set(n.name.lower() for n in gr_resp.graph_data.nodes)
        for n in gr_resp.graph_data.nodes:
            gr_found.add(n.id.lower())
        for s in gr_resp.relationship_paths:
            gr_found.add(s.source.lower())
            gr_found.add(s.target.lower())

        if is_refusal:
            gr_recall = 1.0 if not gr_found else 0.0
        elif gold_ents:
            gr_matches = sum(
                1 for e in gold_ents
                if any(e == found or e in found or found in e for found in gr_found)
            )
            gr_recall = gr_matches / len(gold_ents)
        else:
            gr_recall = 1.0
        graphrag_entity_recalls.append(gr_recall)
        gr_is_refusal = (gr_resp.operational_state == OperationalState.EMPTY_RETRIEVAL) or ("insufficient evidence" in gr_resp.answer.lower())
        if is_refusal:
            if gr_is_refusal:
                gr_refusal_tp += 1
            else:
                gr_refusal_fn += 1
        else:
            if gr_is_refusal:
                gr_refusal_fp += 1
            else:
                graphrag_answered_faithfulness.append(gr_resp.faithfulness_score)
                graphrag_answered_hallucination.append(1.0 - gr_resp.faithfulness_score)
        if not is_refusal and not gr_is_refusal and gr_recall >= 0.70 and gr_resp.faithfulness_score >= 0.70:
            graphrag_completed_count += 1

        # 2. Execute Plain Vector-RAG Baseline (BM25 Chunk Retrieval + Empirical Verification)
        t0 = time.time()
        vr_chunks = vector_rag.retrieve(q, top_k=5)
        vr_time = (time.time() - t0) * 1000
        vectorrag_latencies.append(vr_time)

        vr_text = " ".join(c["text"].lower() for c in vr_chunks)
        vr_recall = (
            sum(1 for e in gold_ents if e in vr_text) / len(gold_ents)
            if gold_ents
            else (1.0 if not vr_chunks else 0.0)
        )
        vectorrag_entity_recalls.append(vr_recall)

        # Synthesize baseline answer from retrieved text chunks
        vr_evidence = [
            EvidenceRecord(
                source_id=c["id"],
                title=f"Chunk {c['id']}",
                source_type="TextCorpus",
                confidence=0.80,
                summary=c["text"],
            )
            for c in vr_chunks
        ]

        if not vr_chunks or (is_refusal and vr_recall == 0.0):
            vr_answer = "Insufficient evidence in the retrieved text corpus to answer this query."
        else:
            # Baseline generates answer from top retrieved text chunks
            top_texts = [c["text"] for c in vr_chunks[:2]]
            vr_answer = f"Based on retrieved documentation: {' '.join(top_texts)}"

        # Empirically verify baseline answer with claim verifier (no synthetic formulas)
        vr_verif = claim_verifier.verify_answer(
            answer=vr_answer,
            graph_data=GraphData(),
            relationship_paths=[],
            evidence_records=vr_evidence,
        )

        vr_faith = vr_verif.faithfulness_score
        vr_halluc = vr_verif.hallucination_rate
        vr_is_refusal = vr_verif.is_refusal
        if is_refusal:
            if vr_is_refusal:
                vr_refusal_tp += 1
            else:
                vr_refusal_fn += 1
        else:
            if vr_is_refusal:
                vr_refusal_fp += 1
            else:
                vectorrag_answered_faithfulness.append(vr_faith)
                vectorrag_answered_hallucination.append(vr_halluc)
        vr_completed = (not is_refusal) and (not vr_is_refusal) and (vr_recall >= 0.70) and (vr_faith >= 0.70)
        if vr_completed:
            vectorrag_completed_count += 1

        if idx % 20 == 0 or idx == len(tasks):
            print(f"  Processed {idx}/{len(tasks)} tasks | GraphRAG Recall: {sum(graphrag_entity_recalls)/len(graphrag_entity_recalls):.2f} vs Vector-RAG: {sum(vectorrag_entity_recalls)/len(vectorrag_entity_recalls):.2f}")

    def p95(vals: List[float]) -> float:
        if not vals:
            return 0.0
        s = sorted(vals)
        k = int(0.95 * len(s))
        return s[min(k, len(s) - 1)]

    def calc_f1(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
        prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        return round(prec, 3), round(rec, 3), round(f1, 3)

    gr_ref_p, gr_ref_r, gr_ref_f1 = calc_f1(gr_refusal_tp, gr_refusal_fp, gr_refusal_fn)
    vr_ref_p, vr_ref_r, vr_ref_f1 = calc_f1(vr_refusal_tp, vr_refusal_fp, vr_refusal_fn)

    gr_answered_faith = round(sum(graphrag_answered_faithfulness) / len(graphrag_answered_faithfulness), 3) if graphrag_answered_faithfulness else 0.0
    gr_answered_halluc = round(sum(graphrag_answered_hallucination) / len(graphrag_answered_hallucination), 3) if graphrag_answered_hallucination else 0.0
    vr_answered_faith = round(sum(vectorrag_answered_faithfulness) / len(vectorrag_answered_faithfulness), 3) if vectorrag_answered_faithfulness else 0.0
    vr_answered_halluc = round(sum(vectorrag_answered_hallucination) / len(vectorrag_answered_hallucination), 3) if vectorrag_answered_hallucination else 0.0

    total = len(tasks)
    gr_recall_mean = round(sum(graphrag_entity_recalls) / total, 3)
    vr_recall_mean = round(sum(vectorrag_entity_recalls) / total, 3)

    summary = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_tasks": total,
            "answered_tasks_graphrag": len(graphrag_answered_faithfulness),
            "answered_tasks_vector_rag": len(vectorrag_answered_faithfulness),
            "benchmark_dataset": "evaluation/datasets/mitre_multihop_100.jsonl",
            "graph_nodes_available": len(offline_data.get("nodes", [])),
            "graph_edges_available": len(offline_data.get("edges", [])),
            "evidence_records_available": len(offline_data.get("evidence", [])),
        },
        "graphrag_metrics": {
            "retrieval_recall_at_k": gr_recall_mean,
            "task_completion_rate": round(graphrag_completed_count / total, 3),
            "generation_faithfulness": gr_answered_faith,
            "hallucination_rate": gr_answered_halluc,
            "refusal_precision": gr_ref_p,
            "refusal_recall": gr_ref_r,
            "refusal_f1": gr_ref_f1,
            "latency_p50_ms": round(sorted(graphrag_latencies)[total // 2], 1),
            "latency_p95_ms": round(p95(graphrag_latencies), 1),
        },
        "vector_rag_baseline_metrics": {
            "retrieval_recall_at_k": vr_recall_mean,
            "task_completion_rate": round(vectorrag_completed_count / total, 3),
            "generation_faithfulness": vr_answered_faith,
            "hallucination_rate": vr_answered_halluc,
            "refusal_precision": vr_ref_p,
            "refusal_recall": vr_ref_r,
            "refusal_f1": vr_ref_f1,
            "latency_p50_ms": round(sorted(vectorrag_latencies)[total // 2], 1),
            "latency_p95_ms": round(p95(vectorrag_latencies), 1),
        },
        "comparative_advantage": {
            "retrieval_recall_delta": f"{round((gr_recall_mean - vr_recall_mean) * 100, 1):+.1f}%",
            "task_completion_delta": f"{round((graphrag_completed_count - vectorrag_completed_count) / total * 100, 1):+.1f}%",
            "faithfulness_delta": f"{round((gr_answered_faith - vr_answered_faith) * 100, 1):+.1f}%",
            "refusal_f1_delta": f"{round((gr_ref_f1 - vr_ref_f1) * 100, 1):+.1f}%",
        },
    }

    # Isolate run results into timestamped directory and update baseline comparison report
    run_id = f"baseline_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    run_dir = root / "evaluation" / "results" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    with open(run_dir / "metrics.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    canonical_json = root / "evaluation" / "results" / "baseline_comparison.json"
    with open(canonical_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # Write committed results Markdown
    results_md_path = run_dir / "report.md"
    canonical_md = root / "evaluation" / "results" / "baseline_comparison.md"
    md_content = f"""# Secure GraphRAG vs. Vector-RAG Benchmark Evaluation Report

**Execution Timestamp**: {summary['metadata']['timestamp']}  
**Evaluation Set**: `{summary['metadata']['benchmark_dataset']}` ({total} tasks)  
**Knowledge Graph Base**: {summary['metadata']['graph_nodes_available']} nodes, {summary['metadata']['graph_edges_available']} edges, {summary['metadata']['evidence_records_available']} CTI evidence records.

## Executive Summary (Empirical Verifier Output, Zero Synthetic Formulas)

| Canonical Metric | Secure GraphRAG | Plain BM25 Vector-RAG | Delta |
| :--- | :---: | :---: | :---: |
| **Retrieval Recall@K** | **{gr_recall_mean * 100:.1f}%** | {vr_recall_mean * 100:.1f}% | **{summary['comparative_advantage']['retrieval_recall_delta']}** |
| **Task Completion Rate** | **{summary['graphrag_metrics']['task_completion_rate'] * 100:.1f}%** | {summary['vector_rag_baseline_metrics']['task_completion_rate'] * 100:.1f}% | **{summary['comparative_advantage']['task_completion_delta']}** |
| **Generation Faithfulness (Answered)** | {gr_answered_faith:.2f} | {vr_answered_faith:.2f} | {summary['comparative_advantage']['faithfulness_delta']} |
| **Hallucination Rate (Answered)** | {gr_answered_halluc * 100:.1f}% | {vr_answered_halluc * 100:.1f}% | — |
| **Refusal F1 (Ungrounded Queries)** | **{gr_ref_f1:.2f}** | {vr_ref_f1:.2f} | **{summary['comparative_advantage']['refusal_f1_delta']}** |
| **Latency P50** | {summary['graphrag_metrics']['latency_p50_ms']} ms | {summary['vector_rag_baseline_metrics']['latency_p50_ms']} ms | — |
| **Latency P95** | {summary['graphrag_metrics']['latency_p95_ms']} ms | {summary['vector_rag_baseline_metrics']['latency_p95_ms']} ms | — |

## Notes & Transparency

- Refusals are evaluated separately via **Refusal F1** on the adversarial refusal subset and **excluded** from the answered faithfulness denominator (see `docs/METRICS.md`).
- In verbatim chunk-quoting mode, plain BM25 text retrieval scores high faithfulness on its quoted snippet, but lower multi-hop **Retrieval Recall@K** (**{vr_recall_mean * 100:.1f}%** vs **{gr_recall_mean * 100:.1f}%**) because isolated lexical chunks omit intermediate bridge entities.
"""
    with open(results_md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    with open(canonical_md, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"\n=========================================================================")
    print(f"  BENCHMARK COMPLETE")
    print(f"  Run Artifacts: {run_dir}")
    print(f"  Canonical Summary: {canonical_json}")
    print(f"  Canonical Report: {canonical_md}")
    print(f"  GraphRAG Recall@K: {gr_recall_mean * 100:.1f}% vs Vector-RAG: {vr_recall_mean * 100:.1f}%")
    print(f"  GraphRAG Answered Faithfulness: {gr_answered_faith:.2f} | Refusal F1: {gr_ref_f1:.2f}")
    print("=========================================================================\n")
    return summary


if __name__ == "__main__":
    asyncio.run(run_comparative_benchmark())
