from __future__ import annotations
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import litellm

log = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    content: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    duration_ms: int

    def parse_json(self) -> Any:
        text = self.content.strip()
        # Tolère les blocs ```json ... ```
        if text.startswith("```"):
            lines = text.splitlines()
            text = "\n".join(line for line in lines if not line.startswith("```"))
        return json.loads(text)


class LLMClient:
    def __init__(self, provider: str, model: str, api_key: str | None,
                 api_base: str | None, supports_cache: bool):
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.api_base = api_base
        self.supports_cache = supports_cache

    def call(self, system: str, user: str, json_mode: bool = False,
             cacheable_system: bool = True) -> LLMResponse:
        """Appelle le LLM, retourne un LLMResponse avec coût et tokens."""
        start = time.perf_counter()

        # Format messages avec ou sans cache_control (Anthropic uniquement)
        if self.supports_cache and cacheable_system and self.provider == "anthropic":
            messages = [
                {
                    "role": "system",
                    "content": [
                        {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
                    ],
                },
                {"role": "user", "content": user},
            ]
        else:
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]

        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 4096,
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.api_base:
            kwargs["api_base"] = self.api_base
        if json_mode and self.provider in ("openai", "google"):
            kwargs["response_format"] = {"type": "json_object"}

        try:
            resp = litellm.completion(**kwargs)
        except Exception as e:
            log.exception("Erreur appel LLM (%s/%s)", self.provider, self.model)
            raise

        duration_ms = int((time.perf_counter() - start) * 1000)
        content = resp.choices[0].message.content or ""

        usage = getattr(resp, "usage", None) or {}
        if hasattr(usage, "model_dump"):
            usage = usage.model_dump()
        input_tokens = int(usage.get("prompt_tokens", 0) or 0)
        output_tokens = int(usage.get("completion_tokens", 0) or 0)

        try:
            cost_usd = float(litellm.completion_cost(completion_response=resp) or 0.0)
        except Exception:
            cost_usd = 0.0

        return LLMResponse(
            content=content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            duration_ms=duration_ms,
        )
