"""
FallbackMultiProvider: Orchestrates an ordered chain of LLM providers with automatic failover and circuit breaker.
"""
from __future__ import annotations

import asyncio
import time
from threading import Lock
from typing import Any, Dict, List, Optional
from app.core.config import settings
from app.core.logging import get_logger
from app.llm.provider import BaseLLMProvider, LLMResponse

logger = get_logger("fallback_provider")


class ProviderStatus:
    def __init__(self, name: str) -> None:
        self.name = name
        self.failures = 0
        self.last_failure_time = 0.0
        self.is_circuit_open = False

    def record_success(self) -> None:
        self.failures = 0
        self.is_circuit_open = False

    def record_failure(self) -> None:
        self.failures += 1
        self.last_failure_time = time.time()
        if self.failures >= 3:
            self.is_circuit_open = True
            logger.warning("provider_circuit_breaker_tripped", name=self.name)

    def is_available(self) -> bool:
        if not self.is_circuit_open:
            return True
        # Cool down circuit breaker after 60s
        if time.time() - self.last_failure_time > 60.0:
            self.is_circuit_open = False
            self.failures = 0
            return True
        return False


class FallbackMultiProvider(BaseLLMProvider):
    """Orchestrates an ordered chain of LLM providers with automatic failover."""

    def __init__(self, providers: Optional[List[BaseLLMProvider]] = None) -> None:
        self.providers = providers or []
        self._statuses: Dict[str, ProviderStatus] = {
            getattr(p, "name", p.__class__.__name__): ProviderStatus(getattr(p, "name", p.__class__.__name__))
            for p in self.providers
        }
        self._lock = Lock()

    async def generate_grounded_answer(
        self, query: str, graph_context: str, **kwargs: Any
    ) -> LLMResponse:
        errors: List[str] = []

        for provider in self.providers:
            name = getattr(provider, "name", provider.__class__.__name__)
            status = self._statuses.setdefault(name, ProviderStatus(name))

            if not status.is_available():
                logger.info("provider_skipped_circuit_open", name=name)
                continue

            logger.info("attempting_llm_generation", name=name)
            try:
                # Bounded per-provider timeout (12s)
                res = await asyncio.wait_for(
                    provider.generate_grounded_answer(query=query, graph_context=graph_context, **kwargs),
                    timeout=12.0,
                )
                status.record_success()
                return res
            except asyncio.TimeoutError:
                logger.warning("provider_attempt_timeout", name=name)
                status.record_failure()
                errors.append(f"{name} timed out after 12s")
            except Exception as e:
                err_msg = str(e)
                logger.warning("provider_attempt_failed", name=name, error=err_msg)
                status.record_failure()
                errors.append(f"{name}: {err_msg}")

        raise RuntimeError(f"All configured LLM providers in fallback chain failed: {'; '.join(errors)}")

    def get_telemetry(self) -> Dict[str, Any]:
        """Return provider reliability and health telemetry."""
        return {
            name: {
                "failures": st.failures,
                "circuit_open": st.is_circuit_open,
                "available": st.is_available(),
            }
            for name, st in self._statuses.items()
        }
