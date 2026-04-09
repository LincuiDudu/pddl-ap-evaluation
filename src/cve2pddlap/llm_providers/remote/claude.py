from __future__ import annotations

import anthropic

from cve2pddlap.llm_providers.llm_provider import LLMProvider
from cve2pddlap.utils.config import get_api_key


class ClaudeProvider(LLMProvider):

    def __init__(self, model: str = "claude-sonnet-4-20250514", max_tokens: int = 4096):
        super().__init__(model, max_tokens)
        self.client = anthropic.Anthropic(api_key=get_api_key("claude"))

    def _send_impl(self, messages: list[dict[str, str]]) -> str:
        # Claude API: system prompt is separate, remaining messages are user/assistant
        system_prompt = ""
        chat_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_prompt = msg["content"]
            else:
                chat_messages.append(msg)

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=chat_messages,
        )
        return response.content[0].text
