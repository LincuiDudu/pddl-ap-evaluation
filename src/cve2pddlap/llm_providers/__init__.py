"""
LLM provider factory.
"""

from cve2pddlap.llm_providers.llm_provider import LLMProvider
from cve2pddlap.utils.config import settings


def create_provider(host: str | None = None, **kwargs) -> LLMProvider:
    """
    Create an LLM provider instance by name.

    Args:
        host: Provider name. Defaults to settings.LLM.model_host.
        **kwargs: Override model, max_tokens, etc.

    Returns:
        LLMProvider instance ready to call .send()
    """
    if host is None:
        host = settings.LLM.model_host

    max_tokens = kwargs.pop("max_tokens", settings.LLM.max_tokens)
    model = kwargs.pop("model", settings.LLM.models[host])

    if host == "gemini":
        from cve2pddlap.llm_providers.remote.gemini import GeminiProvider
        return GeminiProvider(model=model, max_tokens=max_tokens)
    elif host == "deepseek":
        from cve2pddlap.llm_providers.remote.openai_compat import DeepSeekProvider
        return DeepSeekProvider(model=model, max_tokens=max_tokens)
    elif host == "qwen":
        from cve2pddlap.llm_providers.remote.openai_compat import QwenProvider
        return QwenProvider(model=model, max_tokens=max_tokens)
    elif host == "zhipu":
        from cve2pddlap.llm_providers.remote.openai_compat import ZhipuProvider
        return ZhipuProvider(model=model, max_tokens=max_tokens)
    elif host == "claude":
        from cve2pddlap.llm_providers.remote.claude import ClaudeProvider
        return ClaudeProvider(model=model, max_tokens=max_tokens)
    elif host == "gpt4":
        from cve2pddlap.llm_providers.remote.openai_compat import GPT4Provider
        return GPT4Provider(model=model, max_tokens=max_tokens)
    else:
        raise ValueError(f"Unknown LLM provider: {host}")
