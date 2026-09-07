"""
QueryService: End-to-end GraphRAG pipeline orchestrator with verification, failure handling, and observability.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import List, Optional
from fastapi import HTTPException, status
from app.cache.cache import query_cache
from app.core.logging import get_logger
from app.core.telemetry import telemetry_store
from app.evaluation.claim_verifier import claim_verifier
from app.evaluation.confidence import confidence_scorer
from app.evaluation.cost_tracker import cost_tracker
from app.evaluation.escalation_policy import escalation_policy
from app.evaluation.failure_policies import get_failure_policy
from app.llm.factory import get_llm_provider
from app.models.feedback import feedback_store
from app.models.subscription import subscription_store
from app.models.usage import usage_tracker
from app.retrieval.context_builder import context_builder
from app.retrieval.graph_retriever import graph_retriever
from app.retrieval.query_analyzer import query_analyzer
from app.schemas.schemas import (
    ConfidenceLevel,
    EscalationAction,
    GraphData,
    InvestigationProgressStep,
    OperationalState,
    QueryRequest,
    QueryResponse,
    StageTimings,
    TaskCompletionStatus,
)
from app.security.validation import sanitize_for_display, validate_query_input
from app.services.memory_service import memory_service

logger = get_logger("query_service")


class QueryService:
    """End-to-end GraphRAG pipeline orchestrator."""

    async def execute_query(
        self,
        request: QueryRequest,
        user_id: str = "analyst",
        user_role: str = "analyst",
    ) -> QueryResponse:
        start_time = time.time()
        query_id = f"INV-TRC-{uuid.uuid4().hex[:8].upper()}"
        progress_steps: List[InvestigationProgressStep] = []
        timings = StageTimings()

        # Quota enforcement
        allowed, current_usage, daily_limit = usage_tracker.check_and_increment(user_id)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Daily investigation quota of {daily_limit} queries reached for your plan. Upgrade to Pro for 200 daily queries and deep graph traversal.",
            )

        # STAGE 1: Input Validation
        t0 = time.time()
        val_res = validate_query_input(request.query)
        timings.validation_ms = round((time.time() - t0) * 1000, 2)
        if not val_res.is_valid:
            progress_steps.append(
                InvestigationProgressStep(
                    step_name="Input Validation",
                    status="failed",
                    duration_ms=timings.validation_ms,
                    details=val_res.error,
                )
            )
            fail_state = OperationalState.SECURITY_BLOCK if val_res.threat_type in ("cypher_injection", "prompt_injection", "xss") else OperationalState.VALIDATION_FAILURE
            policy = get_failure_policy(fail_state)
            return QueryResponse(
                query_id=query_id,
                query=request.query,
                answer=f"Invalid query input: {val_res.error}",
                confidence=ConfidenceLevel.INSUFFICIENT,
                confidence_explanation="Validation guardrail intercepted query.",
                operational_state=fail_state,
                task_status=TaskCompletionStatus.TASK_FAILED,
                escalation_action=policy.default_escalation,
                graph_data=GraphData(),
                stage_timings=timings,
                progress_steps=progress_steps,
                user_guidance=policy.user_guidance,
            )

        progress_steps.append(
            InvestigationProgressStep(
                step_name="Input Validation",
                status="completed",
                duration_ms=timings.validation_ms,
                details="Sanitized and validated query format.",
            )
        )

        # Contextual Anaphora Resolution via Memory
        effective_query, resolved_entity = memory_service.resolve_contextual_query(
            request.query, request.session_id, user_id
        )

        # STAGE 2: Cache Lookup
        t0 = time.time()
        cached_resp = None if request.bypass_cache else query_cache.get(effective_query, user_id)
        timings.cache_lookup_ms = round((time.time() - t0) * 1000, 2)
        if cached_resp:
            progress_steps.append(
                InvestigationProgressStep(
                    step_name="Cache Lookup",
                    status="completed",
                    duration_ms=timings.cache_lookup_ms,
                    details="Retrieved verified intelligence from memory cache.",
                )
            )
            cached_resp.cached = True
            cached_resp.query_id = query_id
            return cached_resp

        progress_steps.append(
            InvestigationProgressStep(
                step_name="Cache Lookup",
                status="completed",
                duration_ms=timings.cache_lookup_ms,
                details="Cache miss; proceeding to live graph traversal",
            )
        )

        # STAGE 3: Entity Resolution & Query Analysis
        t0 = time.time()
        analysis = query_analyzer.analyze(effective_query)
        timings.query_analysis_ms = round((time.time() - t0) * 1000, 2)

        # Pre-retrieval escalation check (ambiguity, budget)
        pre_decision = escalation_policy.evaluate_pre_retrieval(effective_query)
        if pre_decision and pre_decision.action == EscalationAction.ESCALATE_DISAMBIGUATE:
            policy = get_failure_policy(OperationalState.AMBIGUOUS_ENTITY)
            progress_steps.append(
                InvestigationProgressStep(
                    step_name="Entity Resolution",
                    status="failed",
                    duration_ms=timings.query_analysis_ms,
                    details=pre_decision.reason,
                )
            )
            return QueryResponse(
                query_id=query_id,
                query=effective_query,
                answer="Multiple candidate entities match your query. Please specify which threat entity you wish to investigate.",
                confidence=ConfidenceLevel.LOW,
                confidence_explanation=pre_decision.reason,
                operational_state=OperationalState.AMBIGUOUS_ENTITY,
                task_status=TaskCompletionStatus.AMBIGUOUS_ENTITY,
                escalation_action=EscalationAction.ESCALATE_DISAMBIGUATE,
                graph_data=GraphData(),
                stage_timings=timings,
                progress_steps=progress_steps,
                user_guidance=pre_decision.guidance,
            )

        progress_steps.append(
            InvestigationProgressStep(
                step_name="Entity Resolution",
                status="completed",
                duration_ms=timings.query_analysis_ms,
                details=f"Identified entities: {', '.join(analysis.entities) if analysis.entities else 'Unrecognized terms'}",
            )
        )

        # STAGE 4: Evidence Collection & Graph Retrieval
        t0 = time.time()
        entities_to_query = analysis.entities.copy()
        if not entities_to_query:
            # Check IPs / CVEs
            entities_to_query.extend(analysis.cves)
            entities_to_query.extend(analysis.ip_addresses)

        retrieval_res = await graph_retriever.retrieve_subgraph(
            entity_names=entities_to_query,
            max_depth=request.max_hops,
            intended_rels=analysis.intended_relationships,
        )
        timings.graph_retrieval_ms = round((time.time() - t0) * 1000, 2)

        # Update session memory with first recognized entity
        if retrieval_res.entities_found:
            memory_service.update_session(
                request.session_id or "default", user_id, retrieval_res.entities_found[0], effective_query
            )

        # EMPTY RETRIEVAL SHORT-CIRCUIT:
        # If there are zero relevant entities/paths, DO NOT call LLM. Return immediately with EMPTY_RETRIEVAL.
        if not retrieval_res.graph_data.nodes:
            progress_steps.append(
                InvestigationProgressStep(
                    step_name="Evidence Collection",
                    status="completed",
                    duration_ms=timings.graph_retrieval_ms,
                    details="0 nodes and 0 paths.",
                )
            )
            policy = get_failure_policy(OperationalState.EMPTY_RETRIEVAL)
            timings.total_pipeline_ms = round((time.time() - start_time) * 1000, 2)
            resp = QueryResponse(
                query_id=query_id,
                query=effective_query,
                answer=policy.user_guidance,
                confidence=ConfidenceLevel.INSUFFICIENT,
                confidence_explanation="Insufficient evidence: No verified graph nodes or relationship paths exist in the intelligence base.",
                operational_state=OperationalState.EMPTY_RETRIEVAL,
                task_status=TaskCompletionStatus.TASK_COMPLETED,
                escalation_action=EscalationAction.ESCALATE_REVIEW,
                graph_data=GraphData(),
                stage_timings=timings,
                progress_steps=progress_steps,
                user_guidance=policy.user_guidance,
            )
            telemetry_store.record_query(query_id, timings.total_pipeline_ms, "mock", 0, "INSUFFICIENT")
            return resp

        progress_steps.append(
            InvestigationProgressStep(
                step_name="Evidence Collection",
                status="completed",
                duration_ms=timings.graph_retrieval_ms,
                details=f"Retrieved {len(retrieval_res.graph_data.nodes)} nodes and {len(retrieval_res.relationship_paths)} paths.",
            )
        )

        # STAGE 5: Context Assembly & Budgeting
        t0 = time.time()
        context_str = context_builder.build_context(
            retrieval_res.graph_data,
            retrieval_res.relationship_paths,
            retrieval_res.evidence_records,
            max_token_budget=1500,
        )
        timings.context_assembly_ms = round((time.time() - t0) * 1000, 2)
        progress_steps.append(
            InvestigationProgressStep(
                step_name="Context Assembly",
                status="completed",
                duration_ms=timings.context_assembly_ms,
                details="Assembled context adhering to token budget.",
            )
        )

        # STAGE 6: Grounded AI Generation
        t0 = time.time()
        provider = get_llm_provider()
        llm_error = None
        llm_state = OperationalState.TASK_COMPLETED
        task_status = TaskCompletionStatus.TASK_COMPLETED

        try:
            # Enforce 10-second generation timeout
            llm_res = await asyncio.wait_for(
                provider.generate_grounded_answer(query=effective_query, graph_context=context_str),
                timeout=10.0,
            )
            answer_text = llm_res.answer
            cited_sources = llm_res.cited_sources
            progress_steps.append(
                InvestigationProgressStep(
                    step_name="Grounded AI Generation",
                    status="completed",
                    duration_ms=round((time.time() - t0) * 1000, 2),
                    details="Generated intelligence synthesis constrained to retrieved subgraph",
                )
            )
        except asyncio.TimeoutError:
            logger.warning("llm_generation_timeout", query_id=query_id)
            llm_state = OperationalState.LLM_TIMEOUT
            task_status = TaskCompletionStatus.TASK_COMPLETED
            answer_text = "Analysis timed out while analyzing complex graph paths. The retrieved graph evidence is displayed below for direct analyst review."
            cited_sources = [ev.title for ev in retrieval_res.evidence_records]
            progress_steps.append(
                InvestigationProgressStep(
                    step_name="Grounded AI Generation",
                    status="failed",
                    duration_ms=round((time.time() - t0) * 1000, 2),
                    details="Timed out after 10s. Fell back to deterministic verified graph representation.",
                )
            )
        except Exception as e:
            logger.error("llm_generation_failed", error=str(e))
            llm_state = OperationalState.LLM_PROVIDER_ERROR
            task_status = TaskCompletionStatus.TASK_FAILED
            answer_text = f"AI service encountered an upstream provider error: {str(e)}. Structured graph data has been retrieved safely."
            cited_sources = []
            progress_steps.append(
                InvestigationProgressStep(
                    step_name="Grounded AI Generation",
                    status="failed",
                    duration_ms=round((time.time() - t0) * 1000, 2),
                    details=f"Provider error: {str(e)}",
                )
            )

        timings.llm_generation_ms = round((time.time() - t0) * 1000, 2)

        # Cost Accounting
        cost_rec = cost_tracker.calculate_and_record(
            query_id=query_id,
            prompt_text=context_str,
            completion_text=answer_text,
            model_name=getattr(provider, "model_name", "mock"),
        )

        # STAGE 7: Claim Verification & Confidence Scoring
        t0 = time.time()
        claim_res = claim_verifier.verify_answer(
            answer=answer_text,
            graph_data=retrieval_res.graph_data,
            relationship_paths=retrieval_res.relationship_paths,
            evidence_records=retrieval_res.evidence_records,
        )

        conf_level, conf_expl = confidence_scorer.score(
            retrieval_res.graph_data,
            retrieval_res.relationship_paths,
            retrieval_res.evidence_records,
            is_insufficient_answer=(conf_level_override := "insufficient evidence" in answer_text.lower()),
        )

        # Evaluate escalation post-retrieval
        escalation_dec = escalation_policy.evaluate_post_retrieval(
            retrieval_res.graph_data,
            retrieval_res.evidence_records,
            conf_level,
            claim_res,
        )
        timings.claim_verification_ms = round((time.time() - t0) * 1000, 2)

        progress_steps.append(
            InvestigationProgressStep(
                step_name="Claim Verification & Confidence",
                status="completed",
                duration_ms=timings.claim_verification_ms,
                details=f"Assigned {conf_level.value} confidence | Faithfulness: {claim_res.faithfulness_score:.2f}",
            )
        )

        timings.total_pipeline_ms = round((time.time() - start_time) * 1000, 2)

        response = QueryResponse(
            query_id=query_id,
            query=effective_query,
            answer=claim_res.sanitized_answer or answer_text,
            confidence=conf_level,
            confidence_explanation=conf_expl,
            operational_state=llm_state,
            task_status=task_status,
            escalation_action=escalation_dec.action,
            graph_data=retrieval_res.graph_data,
            relationship_paths=retrieval_res.relationship_paths,
            evidence_records=retrieval_res.evidence_records,
            cited_sources=cited_sources or [ev.title for ev in retrieval_res.evidence_records],
            unsupported_claims=claim_res.unsupported_claims,
            faithfulness_score=claim_res.faithfulness_score,
            cached=False,
            cost_usd=cost_rec.cost_usd,
            stage_timings=timings,
            progress_steps=progress_steps,
            user_guidance=get_failure_policy(llm_state).user_guidance,
        )

        # Cache response if successful and grounded
        if llm_state == OperationalState.TASK_COMPLETED and conf_level in (ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM):
            query_cache.set(effective_query, response, user_id)

        # Record telemetry
        telemetry_store.record_query(
            query_id=query_id,
            latency_ms=timings.total_pipeline_ms,
            model=getattr(provider, "model_name", "mock"),
            tokens=cost_rec.total_tokens,
            confidence=conf_level.value,
        )

        return response


query_service = QueryService()
