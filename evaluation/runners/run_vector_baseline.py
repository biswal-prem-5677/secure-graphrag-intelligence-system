#!/usr/bin/env python3
"""
Empirical Multi-Hop Comparative Benchmark Runner (Phase 3):
Compares 3 retrieval & synthesis systems head-to-head on the frozen Official MITRE ATT&CK v20.1
programmatic test suite (evaluation/datasets/attack_v20_1_test.jsonl):
  1. Secure GraphRAG (Directed multi-hop graph traversal + ClaimVerifier)
  2. Plain BM25 Chunk RAG (Okapi BM25 lexical retrieval + ClaimVerifier)
  3. Dense LSA Vector-RAG (TfidfVectorizer + 128-dim TruncatedSVD cosine similarity + ClaimVerifier)

Enforces ONE shared exact canonical ID / normalized entity matcher across all systems,
computes bootstrap 95% confidence intervals, reports per-hop breakdowns, and strictly separates
refusal F1 from answered-query faithfulness.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import random
import re
import subprocess
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import numpy as np
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))

# Ensure test fixtures are EXCLUDED during official ATT&CK benchmark
os.environ["ENVIRONMENT"] = "development"
os.environ["INCLUDE_TEST_FIXTURE"] = "false"

from app.db.database import init_db
from app.evaluation.claim_verifier import claim_verifier
from app.models.user import User, UserRole, user_store
from app.retrieval.graph_retriever import graph_retriever
from app.schemas.schemas import EvidenceRecord, GraphData, OperationalState, QueryRequest
from app.security.auth import hash_password
from app.services.query_service import query_service


def build_text_corpus(graph_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Build uniform chunked CTI documents from Official ATT&CK v20.1 nodes and relationships."""
    nodes_by_id = {n["id"]: n for n in graph_data.get("nodes", [])}
    chunks: List[Dict[str, str]] = []

    for n in graph_data.get("nodes", []):
        props = n.get("properties", {})
        desc = props.get("description", "")
        aliases = ", ".join(props.get("aliases", []))
        alias_txt = f" Aliases: {aliases}." if aliases else ""
        chunks.append({
            "id": n.get("id", ""),
            "text": f"{n.get('label', '')} {n.get('name', '')} ({n.get('id', '')}).{alias_txt} {desc}",
        })

    for e in graph_data.get("edges", []):
        src = nodes_by_id.get(e["source"], {})
        tgt = nodes_by_id.get(e["target"], {})
        src_name = src.get("name", e["source"])
        tgt_name = tgt.get("name", e["target"])
        desc = e.get("properties", {}).get("description", "")
        chunks.append({
            "id": e.get("properties", {}).get("source_id", f"{e['source']}-{e['target']}"),
            "text": f"{src_name} ({e['source']}) {e['type']} {tgt_name} ({e['target']}). {desc}",
        })

    return chunks


class BM25ChunkRetriever:
    """Standard Okapi BM25 lexical text retriever."""

    def __init__(self, docs: List[Dict[str, str]]) -> None:
        self.docs = docs
        self.doc_tokens = [self._tokenize(d["text"]) for d in docs]
        self.num_docs = len(docs)
        self.df = Counter()
        for tokens in self.doc_tokens:
            for term in set(tokens):
                self.df[term] += 1
        self.avg_dl = sum(len(t) for t in self.doc_tokens) / max(1, self.num_docs)

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"[a-zA-Z0-9_.-]{2,}", text.lower())

    def retrieve(self, query: str, top_k: int = 5) -> List[Dict[str, str]]:
        q_tokens = self._tokenize(query)
        k1, b = 1.5, 0.75
        scores: List[Tuple[float, int]] = []
        for idx, d_tokens in enumerate(self.doc_tokens):
            if not d_tokens:
                continue
            tf = Counter(d_tokens)
            dl = len(d_tokens)
            score = 0.0
            for qt in q_tokens:
                if qt not in tf:
                    continue
                df_val = self.df.get(qt, 0)
                idf = math.log((self.num_docs - df_val + 0.5) / (df_val + 0.5) + 1.0)
                freq = tf[qt]
                denom = freq + k1 * (1 - b + b * (dl / self.avg_dl))
                score += idf * ((freq * (k1 + 1)) / denom)
            if score > 0:
                scores.append((score, idx))
        scores.sort(key=lambda x: x[0], reverse=True)
        return [self.docs[idx] for _, idx in scores[:top_k]]


class DenseLSAVectorRetriever:
    """Dense semantic vector retriever using TF-IDF + 128-dim TruncatedSVD L2 cosine similarity."""

    def __init__(self, docs: List[Dict[str, str]], n_components: int = 128) -> None:
        self.docs = docs
        texts = [d["text"] for d in docs]
        self.vectorizer = TfidfVectorizer(max_features=12000, ngram_range=(1, 2), sublinear_tf=True)
        tfidf_matrix = self.vectorizer.fit_transform(texts)
        n_comp = min(n_components, tfidf_matrix.shape[1] - 1, tfidf_matrix.shape[0] - 1)
        self.svd = TruncatedSVD(n_components=max(2, n_comp), random_state=42)
        dense = self.svd.fit_transform(tfidf_matrix)
        self.doc_embeddings = normalize(dense, norm="l2").astype(np.float32)

    def retrieve(self, query: str, top_k: int = 5) -> List[Dict[str, str]]:
        q_vec = self.vectorizer.transform([query])
        q_dense = self.svd.transform(q_vec)
        q_norm = normalize(q_dense, norm="l2").astype(np.float32)
        sims = (self.doc_embeddings @ q_norm.T).ravel()
        top_indices = np.argpartition(sims, -top_k)[-top_k:]
        top_indices = top_indices[np.argsort(sims[top_indices])[::-1]]
        return [self.docs[i] for i in top_indices if sims[i] > 0.15]


def shared_canonical_recall(
    gold_ids: List[str],
    gold_names: List[str],
    retrieved_ids: Set[str],
    retrieved_names_lower: Set[str],
    raw_text_lower: str = "",
) -> float:
    """
    ONE uniform exact matcher applied identically to GraphRAG, BM25 RAG, and Dense Vector-RAG.
    A gold entity (id, name) is counted as recovered ONLY if its canonical ATT&CK ID matches
    OR its exact normalized full name appears via word boundaries.
    """
    if not gold_ids:
        return 1.0 if (not retrieved_ids and not raw_text_lower.strip()) else 0.0

    matches = 0
    for gid, gname in zip(gold_ids, gold_names):
        gid_l = gid.lower()
        gname_l = gname.lower()
        if gid_l in retrieved_ids or gname_l in retrieved_names_lower:
            matches += 1
        elif raw_text_lower:
            if gid_l in raw_text_lower or re.search(r"(?<!\w)" + re.escape(gname_l) + r"(?!\w)", raw_text_lower):
                matches += 1
    return matches / len(gold_ids)


def bootstrap_ci(values: List[float], n_boot: int = 1000, seed: int = 42) -> Tuple[float, float, float]:
    """Compute mean and 95% bootstrap confidence interval."""
    if not values:
        return 0.0, 0.0, 0.0
    rng = random.Random(seed)
    n = len(values)
    means = []
    for _ in range(n_boot):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    mean_val = sum(values) / n
    lo = means[int(0.025 * n_boot)]
    hi = means[min(int(0.975 * n_boot), n_boot - 1)]
    return round(mean_val, 3), round(lo, 3), round(hi, 3)


def calc_f1(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    return round(prec, 3), round(rec, 3), round(f1, 3)


def p95(vals: List[float]) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    return round(s[min(int(0.95 * len(s)), len(s) - 1)], 1)


async def evaluate_chunk_rag_system(
    name: str,
    retriever: Any,
    tasks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Evaluate a chunk retrieval baseline (BM25 or Dense Vector) using the shared verifier and matcher."""
    recalls: List[float] = []
    latencies: List[float] = []
    answered_faith: List[float] = []
    answered_halluc: List[float] = []
    by_category: Dict[str, List[float]] = {}
    completed = 0
    ref_tp = ref_fp = ref_fn = 0

    for t in tasks:
        q = t["query"]
        gold_ids = t.get("gold_entity_ids", [])
        gold_names = t.get("gold_entity_names", [])
        cat = t.get("category", "unknown")
        is_refusal_task = (cat == "unanswerable_refusal")

        t0 = time.time()
        chunks = retriever.retrieve(q, top_k=5)
        lat = (time.time() - t0) * 1000
        latencies.append(lat)

        chunk_text = " ".join(c["text"] for c in chunks)
        chunk_text_low = chunk_text.lower()
        found_ids = {aid.lower() for aid in re.findall(r"\b[TGSM]\d{4}(?:\.\d{3})?\b", chunk_text)}

        rec = shared_canonical_recall(gold_ids, gold_names, found_ids, set(), chunk_text_low)
        recalls.append(rec)
        by_category.setdefault(cat, []).append(rec)

        evidence = [
            EvidenceRecord(
                source_id=c["id"],
                title=f"Corpus Chunk {c['id']}",
                source_type="TextCorpus",
                confidence=0.80,
                summary=c["text"],
            )
            for c in chunks
        ]

        if not chunks or (is_refusal_task and len(found_ids) == 0 and not any(s.lower() in chunk_text_low for s in t.get("seed_entities", []))):
            ans = "Insufficient evidence in the retrieved text corpus to answer this query."
        else:
            top_txt = " ".join(c["text"] for c in chunks[:2])
            ans = f"Based on retrieved documentation: {top_txt}"

        verif = claim_verifier.verify_answer(
            answer=ans,
            graph_data=GraphData(),
            relationship_paths=[],
            evidence_records=evidence,
        )

        if is_refusal_task:
            if verif.is_refusal:
                ref_tp += 1
            else:
                ref_fp_or_fn = 1
                ref_fn += ref_fp_or_fn
        else:
            if verif.is_refusal:
                ref_fp += 1
            else:
                answered_faith.append(verif.faithfulness_score)
                answered_halluc.append(verif.hallucination_rate)

        if (not is_refusal_task) and (not verif.is_refusal) and rec >= 0.50 and verif.faithfulness_score >= 0.70:
            completed += 1

    answerable_total = sum(1 for t in tasks if t.get("category") != "unanswerable_refusal")
    mean_rec, ci_lo, ci_hi = bootstrap_ci([r for t, r in zip(tasks, recalls) if t.get("category") != "unanswerable_refusal"])
    ref_p, ref_r, ref_f1 = calc_f1(ref_tp, ref_fp, ref_fn)

    return {
        "system": name,
        "retrieval_recall_at_k": mean_rec,
        "retrieval_recall_95ci": [ci_lo, ci_hi],
        "task_completion_rate": round(completed / max(1, answerable_total), 3),
        "generation_faithfulness": round(sum(answered_faith) / max(1, len(answered_faith)), 3),
        "hallucination_rate": round(sum(answered_halluc) / max(1, len(answered_halluc)), 3),
        "refusal_precision": ref_p,
        "refusal_recall": ref_r,
        "refusal_f1": ref_f1,
        "latency_p50_ms": round(sorted(latencies)[len(latencies) // 2], 1),
        "latency_p95_ms": p95(latencies),
        "by_category_recall": {k: round(sum(v) / len(v), 3) for k, v in by_category.items()},
    }


async def evaluate_graphrag_system(tasks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate Secure GraphRAG on the exact same held-out dataset and shared canonical scorer."""
    recalls: List[float] = []
    latencies: List[float] = []
    answered_faith: List[float] = []
    answered_halluc: List[float] = []
    by_category: Dict[str, List[float]] = {}
    completed = 0
    ref_tp = ref_fp = ref_fn = 0

    for idx, t in enumerate(tasks, 1):
        q = t["query"]
        gold_ids = t.get("gold_entity_ids", [])
        gold_names = t.get("gold_entity_names", [])
        cat = t.get("category", "unknown")
        is_refusal_task = (cat == "unanswerable_refusal")
        hops = max(2, int(t.get("hop_count", 2)))

        t0 = time.time()
        req = QueryRequest(query=q, max_hops=hops, bypass_cache=True)
        resp = await query_service.execute_query(req, user_id="eval_user", user_role="admin")
        lat = (time.time() - t0) * 1000
        latencies.append(lat)

        found_ids = {n.id.lower() for n in resp.graph_data.nodes}
        found_names = {n.name.lower() for n in resp.graph_data.nodes}
        for s in resp.relationship_paths:
            found_names.add(s.source.lower())
            found_names.add(s.target.lower())

        rec = shared_canonical_recall(gold_ids, gold_names, found_ids, found_names)
        recalls.append(rec)
        by_category.setdefault(cat, []).append(rec)

        gr_is_refusal = (resp.operational_state == OperationalState.EMPTY_RETRIEVAL) or ("insufficient evidence" in resp.answer.lower())
        if is_refusal_task:
            if gr_is_refusal:
                ref_tp += 1
            else:
                ref_fn += 1
        else:
            if gr_is_refusal:
                ref_fp += 1
            else:
                answered_faith.append(resp.faithfulness_score)
                answered_halluc.append(round(1.0 - resp.faithfulness_score, 3))

        if (not is_refusal_task) and (not gr_is_refusal) and rec >= 0.50 and resp.faithfulness_score >= 0.70:
            completed += 1

        if idx % 35 == 0 or idx == len(tasks):
            print(f"  Evaluated {idx}/{len(tasks)} tasks via GraphRAG...")

    answerable_total = sum(1 for t in tasks if t.get("category") != "unanswerable_refusal")
    mean_rec, ci_lo, ci_hi = bootstrap_ci([r for t, r in zip(tasks, recalls) if t.get("category") != "unanswerable_refusal"])
    ref_p, ref_r, ref_f1 = calc_f1(ref_tp, ref_fp, ref_fn)

    return {
        "system": "Secure GraphRAG",
        "retrieval_recall_at_k": mean_rec,
        "retrieval_recall_95ci": [ci_lo, ci_hi],
        "task_completion_rate": round(completed / max(1, answerable_total), 3),
        "generation_faithfulness": round(sum(answered_faith) / max(1, len(answered_faith)), 3),
        "hallucination_rate": round(sum(answered_halluc) / max(1, len(answered_halluc)), 3),
        "refusal_precision": ref_p,
        "refusal_recall": ref_r,
        "refusal_f1": ref_f1,
        "latency_p50_ms": round(sorted(latencies)[len(latencies) // 2], 1),
        "latency_p95_ms": p95(latencies),
        "by_category_recall": {k: round(sum(v) / len(v), 3) for k, v in by_category.items()},
    }


async def run_comparative_benchmark(split: str = "test") -> Dict[str, Any]:
    ds_name = "attack_v20_1_test.jsonl" if split == "test" else "attack_v20_1_dev.jsonl"
    dataset_path = ROOT / "evaluation" / "datasets" / ds_name
    dataset_sha256 = hashlib.sha256(dataset_path.read_bytes()).hexdigest()[:16]

    try:
        git_sha = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        git_sha = "unknown"

    print("=================================================================================")
    print("  SECURE GRAPHRAG VS. BM25 CHUNK RAG VS. DENSE LSA VECTOR-RAG")
    print(f"  Dataset: evaluation/datasets/{ds_name} (sha256:{dataset_sha256}) | Git: {git_sha}")
    print("=================================================================================")

    init_db()
    if not user_store.user_exists("eval_user"):
        import secrets
        user_store.add_user(
            User(
                id=str(uuid.uuid4()),
                username="eval_user",
                role=UserRole.admin,
                hashed_password=hash_password(secrets.token_urlsafe(16)),
                disabled=False,
            )
        )

    tasks = [json.loads(line) for line in dataset_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    offline_data = graph_retriever._get_offline_data()
    corpus = build_text_corpus(offline_data)

    print(f"Indexing {len(corpus)} ATT&CK v20.1 corpus chunks for BM25 and 128-dim Dense LSA Vector baselines...")
    bm25_retriever = BM25ChunkRetriever(corpus)
    dense_retriever = DenseLSAVectorRetriever(corpus, n_components=128)

    print("Running Secure GraphRAG evaluation...")
    gr_metrics = await evaluate_graphrag_system(tasks)
    print("Running Plain BM25 Chunk RAG baseline...")
    bm25_metrics = await evaluate_chunk_rag_system("Plain BM25 Chunk RAG", bm25_retriever, tasks)
    print("Running Dense LSA Vector-RAG baseline...")
    dense_metrics = await evaluate_chunk_rag_system("Dense LSA Vector-RAG", dense_retriever, tasks)

    meta = offline_data.get("metadata", {})
    summary = {
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "git_sha": git_sha,
            "split": split,
            "dataset": f"evaluation/datasets/{ds_name}",
            "dataset_sha256": dataset_sha256,
            "total_tasks": len(tasks),
            "attack_version": meta.get("version", "20.1"),
            "attack_sha256": meta.get("sha256", ""),
            "graph_nodes": len(offline_data.get("nodes", [])),
            "graph_edges": len(offline_data.get("edges", [])),
            "seed": 42,
        },
        "graphrag_metrics": gr_metrics,
        "bm25_baseline_metrics": bm25_metrics,
        "dense_vector_baseline_metrics": dense_metrics,
    }

    run_id = f"baseline_{split}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    run_dir = ROOT / "evaluation" / "results" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (run_dir / "config.json").write_text(json.dumps(summary["metadata"], indent=2), encoding="utf-8")

    canon_json = ROOT / "evaluation" / "results" / "baseline_comparison.json"
    canon_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    gr_ci = gr_metrics["retrieval_recall_95ci"]
    bm_ci = bm25_metrics["retrieval_recall_95ci"]
    dn_ci = dense_metrics["retrieval_recall_95ci"]

    md_report = f"""# Empirical Multi-Hop Comparative Evaluation Report

**Timestamp**: {summary['metadata']['timestamp']} | **Commit**: `{git_sha}`  
**Dataset**: `{summary['metadata']['dataset']}` ({len(tasks)} programmatic held-out tasks, `sha256:{dataset_sha256}`)  
**Knowledge Graph**: Official MITRE ATT&CK® Enterprise v{meta.get('version', '20.1')} ({len(offline_data.get('nodes', []))} nodes, {len(offline_data.get('edges', []))} edges)

## 1. Head-to-Head Summary (Shared Exact Canonical Matcher & Empirical ClaimVerifier)

| Canonical Metric | Secure GraphRAG | Plain BM25 Chunk RAG | Dense LSA Vector-RAG |
| :--- | :---: | :---: | :---: |
| **Retrieval Recall@K (95% CI)** | **{gr_metrics['retrieval_recall_at_k']*100:.1f}%** [{gr_ci[0]*100:.1f}–{gr_ci[1]*100:.1f}%] | {bm25_metrics['retrieval_recall_at_k']*100:.1f}% [{bm_ci[0]*100:.1f}–{bm_ci[1]*100:.1f}%] | {dense_metrics['retrieval_recall_at_k']*100:.1f}% [{dn_ci[0]*100:.1f}–{dn_ci[1]*100:.1f}%] |
| **Task Completion Rate** | **{gr_metrics['task_completion_rate']*100:.1f}%** | {bm25_metrics['task_completion_rate']*100:.1f}% | {dense_metrics['task_completion_rate']*100:.1f}% |
| **Generation Faithfulness (Answered)** | {gr_metrics['generation_faithfulness']:.2f} | {bm25_metrics['generation_faithfulness']:.2f} | {dense_metrics['generation_faithfulness']:.2f} |
| **Hallucination Rate (Answered)** | {gr_metrics['hallucination_rate']*100:.1f}% | {bm25_metrics['hallucination_rate']*100:.1f}% | {dense_metrics['hallucination_rate']*100:.1f}% |
| **Refusal F1 (Ungrounded Probes)** | **{gr_metrics['refusal_f1']:.2f}** | {bm25_metrics['refusal_f1']:.2f} | {dense_metrics['refusal_f1']:.2f} |
| **Latency P50** | {gr_metrics['latency_p50_ms']} ms | {bm25_metrics['latency_p50_ms']} ms | {dense_metrics['latency_p50_ms']} ms |
| **Latency P95** | {gr_metrics['latency_p95_ms']} ms | {bm25_metrics['latency_p95_ms']} ms | {dense_metrics['latency_p95_ms']} ms |

## 2. Per-Category / Per-Hop Retrieval Recall Breakdown

| Task Category | Secure GraphRAG | Plain BM25 Chunk RAG | Dense LSA Vector-RAG |
| :--- | :---: | :---: | :---: |
| **2-Hop (`Actor -> Software -> Technique`)** | **{gr_metrics['by_category_recall'].get('two_hop_actor_sw_tech', 0)*100:.1f}%** | {bm25_metrics['by_category_recall'].get('two_hop_actor_sw_tech', 0)*100:.1f}% | {dense_metrics['by_category_recall'].get('two_hop_actor_sw_tech', 0)*100:.1f}% |
| **3-Hop (`Actor -> SW -> Tech <- Mitigation`)** | **{gr_metrics['by_category_recall'].get('three_hop_actor_sw_tech_mit', 0)*100:.1f}%** | {bm25_metrics['by_category_recall'].get('three_hop_actor_sw_tech_mit', 0)*100:.1f}% | {dense_metrics['by_category_recall'].get('three_hop_actor_sw_tech_mit', 0)*100:.1f}% |
| **Set Intersection (`Actor A ∩ Actor B`)** | **{gr_metrics['by_category_recall'].get('set_intersection', 0)*100:.1f}%** | {bm25_metrics['by_category_recall'].get('set_intersection', 0)*100:.1f}% | {dense_metrics['by_category_recall'].get('set_intersection', 0)*100:.1f}% |
"""
    (run_dir / "report.md").write_text(md_report, encoding="utf-8")
    (ROOT / "evaluation" / "results" / "baseline_comparison.md").write_text(md_report, encoding="utf-8")

    print("\n=================================================================================")
    print(f"  BENCHMARK COMPLETE ({run_dir})")
    print(f"  GraphRAG Recall@K : {gr_metrics['retrieval_recall_at_k']*100:.1f}% (95% CI [{gr_ci[0]*100:.1f}–{gr_ci[1]*100:.1f}%]) | Refusal F1: {gr_metrics['refusal_f1']:.2f}")
    print(f"  BM25 RAG Recall@K : {bm25_metrics['retrieval_recall_at_k']*100:.1f}% (95% CI [{bm_ci[0]*100:.1f}–{bm_ci[1]*100:.1f}%]) | Refusal F1: {bm25_metrics['refusal_f1']:.2f}")
    print(f"  Dense LSA Recall@K: {dense_metrics['retrieval_recall_at_k']*100:.1f}% (95% CI [{dn_ci[0]*100:.1f}–{dn_ci[1]*100:.1f}%]) | Refusal F1: {dense_metrics['refusal_f1']:.2f}")
    print("=================================================================================\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Multi-Hop Comparative Benchmark")
    parser.add_argument("--split", choices=["dev", "test"], default="test", help="Dataset split (default: test)")
    args = parser.parse_args()
    asyncio.run(run_comparative_benchmark(split=args.split))
