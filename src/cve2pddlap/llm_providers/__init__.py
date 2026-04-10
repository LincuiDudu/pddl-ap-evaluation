"""
LLM provider factory.
"""

from cve2pddlap.llm_providers.llm_provider import LLMProvider
from cve2pddlap.utils.config import settings

# Local provider defaults (reproducibility)
_LOCAL_DEFAULTS = dict(
    temperature=settings.LLM.local.temperature,  # 0.0
    seed=int(settings.LLM.local.seed),           # 42
    top_p=settings.LLM.local.top_p,              # 1.0
)

# All available hosts for UI
ALL_HOSTS = [
    # Remote API
    "qwen", "deepseek", "claude", "gpt4", "gemini", "zhipu",
    # Local / LAN
    "deepseek_r1_ollama",
    "qwen3b", "qwen7b", "qwen14b", "qwen7b_coder",
]


def create_provider(host: str | None = None, **kwargs) -> LLMProvider:
    """
    Create an LLM provider instance by name.

    Args:
        host: Provider name. One of ALL_HOSTS. Defaults to settings.LLM.model_host.
        **kwargs: Override model, max_tokens, temperature, seed, top_p, etc.
                  Local providers default to temperature=0, seed=42, top_p=1.

    Returns:
        LLMProvider instance ready to call .send()
    """
    if host is None:
        host = settings.LLM.model_host

    max_tokens = kwargs.pop("max_tokens", settings.LLM.max_tokens)
    temperature = kwargs.pop("temperature", None)
    seed = kwargs.pop("seed", None)
    top_p = kwargs.pop("top_p", None)

    # --- Remote providers (with full parameter control) ---
    if host == "gemini":
        from cve2pddlap.llm_providers.remote.gemini import GeminiProvider
        model = kwargs.pop("model", getattr(settings.LLM.models, host))
        return GeminiProvider(model=model, max_tokens=max_tokens,
                              temperature=temperature, seed=seed, top_p=top_p)

    elif host in ("deepseek", "qwen", "zhipu", "gpt4"):
        from cve2pddlap.llm_providers.remote.openai_compat import (
            DeepSeekProvider, QwenProvider, ZhipuProvider, GPT4Provider,
        )
        cls = {"deepseek": DeepSeekProvider, "qwen": QwenProvider,
               "zhipu": ZhipuProvider, "gpt4": GPT4Provider}[host]
        model = kwargs.pop("model", getattr(settings.LLM.models, host))
        return cls(model=model, max_tokens=max_tokens, temperature=temperature, **kwargs)

    elif host == "claude":
        from cve2pddlap.llm_providers.remote.claude import ClaudeProvider
        model = kwargs.pop("model", getattr(settings.LLM.models, host))
        return ClaudeProvider(model=model, max_tokens=max_tokens, temperature=temperature)

    # --- Ollama providers (LAN) ---
    elif host == "deepseek_r1_ollama":
        from cve2pddlap.llm_providers.remote.ollama import DeepSeekR1OllamaProvider
        return DeepSeekR1OllamaProvider(
            max_tokens=max_tokens,
            temperature=temperature if temperature is not None else 0.0,
        )

    # --- Local vLLM providers ---
    elif host in ("qwen3b", "qwen7b", "qwen14b", "qwen7b_coder"):
        from cve2pddlap.llm_providers.remote.vllm import (
            Qwen3BProvider, Qwen7BProvider, Qwen14BProvider, Qwen7BCoderProvider,
        )
        cls = {
            "qwen3b": Qwen3BProvider,
            "qwen7b": Qwen7BProvider,
            "qwen14b": Qwen14BProvider,
            "qwen7b_coder": Qwen7BCoderProvider,
        }[host]
        params = {**_LOCAL_DEFAULTS, **kwargs}
        params["max_tokens"] = max_tokens
        if temperature is not None:
            params["temperature"] = temperature
        if seed is not None:
            params["seed"] = seed
        if top_p is not None:
            params["top_p"] = top_p
        return cls(**params)

    else:
        raise ValueError(f"Unknown LLM provider: {host!r}")
