from __future__ import annotations
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    db_url: str
    provider: str
    model: str
    api_key: str | None
    api_base: str | None
    daily_budget_usd: float
    triage_max_findings: int
    cache_ttl_seconds: int
    sql_row_limit: int

    @classmethod
    def from_env(cls) -> "Config":
        provider = os.environ.get("LLM_PROVIDER", "anthropic").lower()
        default_models = {
            "anthropic": "claude-sonnet-4-6",
            "openai": "gpt-4o-mini",
            "google": "gemini-1.5-flash",
            "ollama": "llama3.1:8b",
        }
        api_key_envs = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "google": "GEMINI_API_KEY",
            "ollama": None,
        }
        # Important : utiliser `or` plutôt que `os.environ.get(..., default)` car les
        # valeurs vides ("") dans le .env doivent retomber sur le défaut.
        return cls(
            db_url=os.environ["DB_URL"],
            provider=provider,
            model=os.environ.get("LLM_MODEL") or default_models.get(provider, "claude-sonnet-4-6"),
            api_key=(os.environ.get(api_key_envs[provider]) or None) if api_key_envs.get(provider) else None,
            api_base=os.environ.get("LLM_API_BASE") or None,
            daily_budget_usd=float(os.environ.get("LLM_DAILY_BUDGET_USD") or "2.0"),
            triage_max_findings=int(os.environ.get("TRIAGE_MAX_FINDINGS") or "100"),
            cache_ttl_seconds=int(os.environ.get("LLM_CACHE_TTL") or "300"),
            sql_row_limit=int(os.environ.get("CHAT_SQL_ROW_LIMIT") or "200"),
        )

    @property
    def litellm_model(self) -> str:
        if self.provider == "anthropic":
            return f"anthropic/{self.model}"
        if self.provider == "openai":
            return f"openai/{self.model}"
        if self.provider == "google":
            return f"gemini/{self.model}"
        if self.provider == "ollama":
            return f"ollama/{self.model}"
        return self.model

    @property
    def supports_cache(self) -> bool:
        return self.provider == "anthropic"
