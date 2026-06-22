from __future__ import annotations

from google import genai
from google.genai import types

from cve2pddlap.llm_providers.llm_provider import LLMProvider
from cve2pddlap.utils.config import get_api_key


class GeminiProvider(LLMProvider):

    def __init__(self, model: str = "gemini-2.0-flash", max_tokens: int = 4096,
                 temperature: float | None = None, seed: int | None = None,
                 top_p: float | None = None):
        super().__init__(model, max_tokens, temperature, seed, top_p)
        self.client = genai.Client(api_key=get_api_key("gemini"))

    def _send_impl(self, messages: list[dict[str, str]]) -> str:
        system_prompt = ""
        contents = []
        for msg in messages:
            if msg["role"] == "system":
                system_prompt = msg["content"]
            else:
                role = "model" if msg["role"] == "assistant" else "user"
                contents.append(types.Content(
                    role=role,
                    parts=[types.Part(text=msg["content"])],
                ))

        config_kwargs = dict(
            system_instruction=system_prompt,
            max_output_tokens=self.max_tokens,
        )
        if self.temperature is not None:
            config_kwargs["temperature"] = self.temperature
        if self.top_p is not None:
            config_kwargs["top_p"] = self.top_p
        if self.seed is not None:
            config_kwargs["seed"] = self.seed

        response = self.client.models.generate_content(
            model=self.model,
            config=types.GenerateContentConfig(**config_kwargs),
            contents=contents,
        )
        return response.text
