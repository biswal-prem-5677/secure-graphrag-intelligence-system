"""
Ollama local server inference provider for 100% private, zero-cloud-cost operation.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
import httpx
from app.core.config import settings
from app.core.logging import get_logger
from app.llm.prompts import GRAPHRAG_SYSTEM_PROMPT, GRAPHRAG_USER_TEMPLATE
from app.llm.provider import BaseLLMProvider, LLMResponse

logger = get_logger("ollama_provider")


class OllamaProvider(BaseLLMProvider):
    """Ollama local server inference provider."""

    def __init__(self) -> None:
        self.base_url = settings.OLLAMA_BASE_URL.rstrip("/")
        self.model_name = settings.OLLAMA_MODEL

    async def generate_grounded_answer(
        self, query: str, graph_context: str, **kwargs: Any
    ) -> LLMResponse:
        endpoint = f"{self.base_url}/api/generate"
        prompt = (
            f"{GRAPHRAG_SYSTEM_PROMPT}\n\n"
            f"{GRAPHRAG_USER_TEMPLATE.format(query=query, graph_context=graph_context)}"
        )

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1},
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(endpoint, json=payload)
                if resp.status_code != 200:
                    raise RuntimeError(f"Ollama inference error ({resp.status_code}): {resp.text}")
                data = resp.json()
                answer_text = data.get("response", "")

                cited = re.findall(r"(?:Report|Advisory|Analysis|IR-\d+|TR-\d+|CERT-\d+)[^,\n.]*", answer_text)
                confidence = "HIGH"
                if "insufficient evidence" in answer_text.lower():
                    confidence = "INSUFFICIENT"
                elif not cited:
                    confidence = "MEDIUM"

                return LLMResponse(
                    answer=answer_text,
                    confidence=confidence,
                    confidence_explanation=f"Generated locally by Ollama ({self.model_name}) adhering to grounded graph context.",
                    cited_sources=list(set(cited)),
                    raw_response=data,
                )
        except httpx.ConnectError as e:
            raise RuntimeError(f"Ollama server not reachable at {self.base_url}. Ensure Ollama is running ('ollama serve').") from e
