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

# Tier-grouped host list for UI display.
# Each entry is either a host name (str) or a separator label (starts with "──").
# The widget uses (label, value) tuples so separators are visible but unselectable.
ALL_HOSTS_TIERED = [
    # ── Large ────────────────────────────────────────────────────────
    ("── Large ───────────────────────────", None),
    ("Claude Sonnet 4.5            [paid]", "claude"),
    ("GPT-4o-mini                   [paid]", "gpt4"),
    ("DeepSeek-R1 (reasoning)      [paid]", "deepseek_r1"),
    ("Mistral Large                [paid]", "mistral_large"),
    ("Groq · Llama 3.3 70B         [free]", "groq_llama"),
    # ── Mid ──────────────────────────────────────────────────────────
    ("── Mid ─────────────────────────────", None),
    ("Qwen-Plus                    [paid]", "qwen"),
    ("DeepSeek-Chat                [paid]", "deepseek"),
    ("Gemini 2.0 Flash             [paid]", "gemini"),
    ("Zhipu GLM-4-Flash            [paid]", "zhipu"),
    ("Mistral Small                [free]", "mistral_small"),
    ("Groq · Mixtral 8x7B          [free]", "groq_mixtral"),
    # ── Small (Local / LAN) ──────────────────────────────────────────
    ("── Small (Local) ───────────────────", None),
    ("DeepSeek-R1 7B  (Ollama LAN) [free]", "deepseek_r1_ollama"),
    ("Qwen2.5-3B      (vLLM local) [free]", "qwen3b"),
    ("Qwen2.5-7B      (vLLM local) [free]", "qwen7b"),
    ("Qwen2.5-14B     (vLLM local) [free]", "qwen14b"),
    ("Qwen2.5-Coder-7B(vLLM local) [free]", "qwen7b_coder"),
]

# Flat list of valid host names (no separators) — for backwards compatibility
ALL_HOSTS = [v for _, v in ALL_HOSTS_TIERED if v is not None]

# Model tier lookup: "large" | "mid" | "small"
# Controls default SMI inclusion in few-shot mode:
#   large/mid → SMI optional (model is capable enough)
#   small     → SMI auto-selected (weaker models need structural guidance)
MODEL_TIER: dict[str, str] = {
    # Large / reasoning
    "claude":        "large",
    "gpt4":          "large",
    "deepseek_r1":   "large",
    "mistral_large": "large",
    "groq_llama":    "large",
    # Mid-tier commercial API
    "qwen":          "mid",
    "deepseek":      "mid",
    "gemini":        "mid",
    "zhipu":         "mid",
    "mistral_small": "mid",
    "groq_mixtral":  "mid",
    # Small / local
    "deepseek_r1_ollama": "small",
    "qwen3b":        "small",
    "qwen7b":        "small",
    "qwen14b":       "small",
    "qwen7b_coder":  "small",
}

# Which parameters each provider supports (claude has no seed)
_PROVIDER_CAPS = {
    "claude":        {"temperature", "top_p"},
    "gpt4":          {"temperature", "seed", "top_p"},
    "deepseek_r1":   {"temperature", "seed", "top_p"},
    "mistral_large": {"temperature", "seed", "top_p"},
    "groq_llama":    {"temperature", "seed", "top_p"},
    "qwen":          {"temperature", "seed", "top_p"},
    "deepseek":      {"temperature", "seed", "top_p"},
    "gemini":        {"temperature", "seed", "top_p"},
    "zhipu":         {"temperature", "seed", "top_p"},
    "mistral_small": {"temperature", "seed", "top_p"},
    "groq_mixtral":  {"temperature", "seed", "top_p"},
}


def create_provider(host: str | None = None, **kwargs) -> LLMProvider:
    """
    Create an LLM provider instance by name.

    Args:
        host: Provider name. One of ALL_HOSTS. Defaults to settings.LLM.model_host.
        **kwargs: Override model, max_tokens, temperature, seed, top_p, etc.
                  Local/LAN providers default to temperature=0, seed=42, top_p=1.

    Returns:
        LLMProvider instance ready to call .send()
    """
    if host is None:
        host = settings.LLM.model_host

    max_tokens = kwargs.pop("max_tokens", settings.LLM.max_tokens)
    temperature = kwargs.pop("temperature", None)
    seed = kwargs.pop("seed", None)
    top_p = kwargs.pop("top_p", None)

    # --- Remote providers ---
    if host == "gemini":
        from cve2pddlap.llm_providers.remote.gemini import GeminiProvider
        model = kwargs.pop("model", getattr(settings.LLM.models, host))
        return GeminiProvider(model=model, max_tokens=max_tokens,
                              temperature=temperature, seed=seed, top_p=top_p)

    elif host == "claude":
        from cve2pddlap.llm_providers.remote.claude import ClaudeProvider
        model = kwargs.pop("model", getattr(settings.LLM.models, host))
        return ClaudeProvider(model=model, max_tokens=max_tokens,
                              temperature=temperature, top_p=top_p)

    elif host in ("deepseek", "deepseek_r1", "qwen", "zhipu", "gpt4",
                  "mistral_small", "mistral_large", "groq_llama", "groq_mixtral"):
        from cve2pddlap.llm_providers.remote.openai_compat import (
            DeepSeekProvider, QwenProvider, ZhipuProvider, GPT4Provider,
            MistralProvider, GroqProvider,
        )
        cls_map = {
            "deepseek":      DeepSeekProvider,
            "deepseek_r1":   DeepSeekProvider,
            "qwen":          QwenProvider,
            "zhipu":         ZhipuProvider,
            "gpt4":          GPT4Provider,
            "mistral_small": MistralProvider,
            "mistral_large": MistralProvider,
            "groq_llama":    GroqProvider,
            "groq_mixtral":  GroqProvider,
        }
        cls = cls_map[host]
        model = kwargs.pop("model", getattr(settings.LLM.models, host))
        return cls(model=model, max_tokens=max_tokens,
                   temperature=temperature, seed=seed, top_p=top_p)

    # --- Ollama providers (LAN) ---
    elif host == "deepseek_r1_ollama":
        from cve2pddlap.llm_providers.remote.ollama import DeepSeekR1OllamaProvider
        params = {**_LOCAL_DEFAULTS}
        params["max_tokens"] = max_tokens
        if temperature is not None:
            params["temperature"] = temperature
        if seed is not None:
            params["seed"] = seed
        if top_p is not None:
            params["top_p"] = top_p
        return DeepSeekR1OllamaProvider(**params)

    # --- Local vLLM providers ---
    elif host in ("qwen3b", "qwen7b", "qwen14b", "qwen7b_coder"):
        from cve2pddlap.llm_providers.remote.vllm import (
            Qwen3BProvider, Qwen7BProvider, Qwen14BProvider, Qwen7BCoderProvider,
        )
        cls = {
            "qwen3b":       Qwen3BProvider,
            "qwen7b":       Qwen7BProvider,
            "qwen14b":      Qwen14BProvider,
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
