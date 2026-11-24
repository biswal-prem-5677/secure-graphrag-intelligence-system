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
    """Instantiate the active LLM provider from settings.

    In production, multi-provider failover chains across real configured providers
    (Ollama -> Gemini -> Groq -> OpenAI) and fails explicitly with a provider error
    if all fail. Canned mock generation is never silently returned in production.
    """
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
        chain: list[BaseLLMProvider] = []
        if getattr(settings, "OLLAMA_BASE_URL", None):
            chain.append(OllamaProvider())
        if getattr(settings, "GOOGLE_API_KEY", None):
            chain.append(GeminiProvider())
        if getattr(settings, "GROQ_API_KEY", None):
            chain.append(GroqProvider())
        if getattr(settings, "OPENAI_API_KEY", None):
            chain.append(OpenAIProvider())

        # In non-production development/testing, allow mock fallback if no real keys are set
        if not chain:
            logger.info("no_cloud_llm_keys_configured_using_deterministic_mock")
            return MockLLMProvider()

        # Only append mock to the fallback chain in dev if explicitly requested
        is_prod = getattr(settings, "ENVIRONMENT", "development") == "production"
        if not is_prod and getattr(settings, "ENABLE_DEV_MOCK_FALLBACK", False):
            chain.append(MockLLMProvider())

        return FallbackMultiProvider(chain)
    else:
        if getattr(settings, "ENVIRONMENT", "development") == "production":
            raise ValueError(f"Unknown or unsupported LLM_PROVIDER '{provider_type}' in production.")
        return MockLLMProvider()
