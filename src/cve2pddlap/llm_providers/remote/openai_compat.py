"""
OpenAI-compatible providers: DeepSeek, Qwen, Zhipu, GPT-4.
All use the OpenAI SDK with different base_url / api_key / model.
"""

from __future__ import annotations

from openai import OpenAI

from cve2pddlap.llm_providers.llm_provider import LLMProvider
from cve2pddlap.utils.config import get_api_key, settings


class OpenAICompatProvider(LLMProvider):
    """Base for any provider using OpenAI-compatible chat API."""

    def __init__(self, provider_name: str, model: str, max_tokens: int = 4096,
                 base_url: str | None = None):
        super().__init__(model, max_tokens)
        api_key = get_api_key(provider_name)
        self.client = OpenAI(api_key=api_key, base_url=base_url)

    def _send_impl(self, messages: list[dict[str, str]]) -> str:
        # OpenAI API accepts messages list directly (system + user + assistant...)
        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=self.max_tokens,
        )
        return response.choices[0].message.content


class DeepSeekProvider(OpenAICompatProvider):
    def __init__(self, model: str = "deepseek-chat", max_tokens: int = 4096):
        super().__init__("deepseek", model, max_tokens,
                         base_url=settings.LLM.endpoints.deepseek)


class QwenProvider(OpenAICompatProvider):
    def __init__(self, model: str = "qwen-plus", max_tokens: int = 4096):
        super().__init__("qwen", model, max_tokens,
                         base_url=settings.LLM.endpoints.qwen)


class ZhipuProvider(OpenAICompatProvider):
    def __init__(self, model: str = "glm-4-flash", max_tokens: int = 4096):
        super().__init__("zhipu", model, max_tokens,
                         base_url=settings.LLM.endpoints.zhipu)


class GPT4Provider(OpenAICompatProvider):
    def __init__(self, model: str = "gpt-4o", max_tokens: int = 4096):
        super().__init__("gpt4", model, max_tokens)
