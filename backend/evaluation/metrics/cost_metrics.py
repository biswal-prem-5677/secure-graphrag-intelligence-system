from typing import Any, Dict


def estimate_token_count(text: str) -> int:
    """Estimate token count based on average word-to-token ratio (~1.3 tokens per word)."""
    if not text:
        return 0
    words = len(text.strip().split())
    return max(1, int(words * 1.3))


def calculate_query_cost(prompt_tokens: int, completion_tokens: int, model_name: str = "mock") -> Dict[str, Any]:
    """Calculate token consumption and estimated monetary cost in USD."""
    rates = {
        "gemini-2.0-flash": (0.10, 0.40),
        "llama-3.3-70b-versatile": (0.59, 0.79),
        "gpt-4o-mini": (0.15, 0.60),
        "mock": (0.0, 0.0),
    }
    input_rate, output_rate = rates.get(model_name, (0.20, 0.60))
    cost = (prompt_tokens / 1_000_000 * input_rate) + (completion_tokens / 1_000_000 * output_rate)
    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
        "cost_usd": round(cost, 6),
    }
