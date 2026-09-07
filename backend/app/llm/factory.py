"""
Factory to instantiate the active LLM provider based on application configuration.
"""
from __future__ import annotations

from app.core.config import settings
from app.llm.fallback_provider import FallbackMultiProvider
from app.llm.gemini_provider import GeminiProvider
from app.llm.groq_provider import GroqProvider
from app.llm.mock_provider import MockLLMProvider
from app.llm.ollama_provider import OllamaProvider
from app.llm.openai_provider import OpenAIProvider
from app.llm.provider import BaseLLMProvider


def get_llm_provider() -> BaseLLMProvider:
    """Instantiate the active LLM provider from settings."""
    provider_type = settings.LLM_PROVIDER.lower().strip()

    if provider_type == "mock":
        return MockLLMProvider()
    elif provider_type == "gemini":
        return GeminiProvider()
    elif provider_type == "groq":
        return GroqProvider()
    elif provider_type == "ollama":
        return OllamaProvider()
    elif provider_type == "openai":
        return OpenAIProvider()
    elif provider_type == "multi":
        # Free-first fallback ordering: Ollama (local) -> Gemini (free tier) -> Groq (free tier) -> Mock
        chain: list[BaseLLMProvider] = []
        if settings.OLLAMA_BASE_URL:
            chain.append(OllamaProvider())
        if settings.GOOGLE_API_KEY:
            chain.append(GeminiProvider())
        if settings.GROQ_API_KEY:
            chain.append(GroqProvider())
        if settings.OPENAI_API_KEY:
            chain.append(OpenAIProvider())
        chain.append(MockLLMProvider())
        return FallbackMultiProvider(chain)
    else:
        return MockLLMProvider()
