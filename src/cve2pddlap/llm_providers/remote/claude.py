from __future__ import annotations

import anthropic

from cve2pddlap.llm_providers.llm_provider import LLMProvider
from cve2pddlap.utils.config import get_api_key


class ClaudeProvider(LLMProvider):
    """
    Claude API provider.
    Supports: temperature, top_p, top_k.
    Note: Claude API does NOT support seed parameter.
    """

    def __init__(self, model: str = "claude-sonnet-4-20250514", max_tokens: int = 4096,
                 temperature: float | None = None, top_p: float | None = None,
                 top_k: int | None = None):
        super().__init__(model, max_tokens, temperature, seed=None, top_p=top_p)
        self.top_k = top_k
        self.client = anthropic.Anthropic(api_key=get_api_key("claude"))

    def _send_impl(self, messages: list[dict[str, str]]) -> str:
        system_prompt = ""
        chat_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_prompt = msg["content"]
            else:
                chat_messages.append(msg)

        kwargs = dict(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=chat_messages,
        )
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if self.top_p is not None:
            kwargs["top_p"] = self.top_p
        if self.top_k is not None:
            kwargs["top_k"] = self.top_k

        response = self.client.messages.create(**kwargs)
        return response.content[0].text
