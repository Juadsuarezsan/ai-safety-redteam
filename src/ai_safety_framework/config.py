"""Environment-driven configuration.

Every knob comes from the environment (or a ``.env`` file) and is read through
:func:`get_settings`, which caches a single :class:`Settings` instance.
Tests that mutate the environment call ``get_settings.cache_clear()``.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PINNED_MODEL = "claude-sonnet-4-5-20250929"
"""Dated model ID used both as system-under-test and as red-teamer/judge."""


class Settings(BaseSettings):
    """Runtime settings. See ``.env.example`` for the meaning of each variable."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default=PINNED_MODEL, alias="ANTHROPIC_MODEL")
    anthropic_timeout_s: float = Field(default=60.0, alias="ANTHROPIC_TIMEOUT_S")
    anthropic_max_retries: int = Field(default=3, alias="ANTHROPIC_MAX_RETRIES")

    target_system_url: str = Field(default="http://localhost:8001", alias="TARGET_SYSTEM_URL")
    target_adapter: str = Field(default="chat", alias="TARGET_ADAPTER")
    target_api_key: str | None = Field(default=None, alias="TARGET_API_KEY")
    target_timeout_s: float = Field(default=30.0, alias="TARGET_TIMEOUT_S")
    target_max_retries: int = Field(default=3, alias="TARGET_MAX_RETRIES")
    max_concurrency: int = Field(default=8, alias="MAX_CONCURRENCY")

    enable_guardrails: bool = Field(default=True, alias="ENABLE_GUARDRAILS")
    guardrails_mode: str = Field(default="regex", alias="GUARDRAILS_MODE")

    cors_origins: str = Field(
        default="http://localhost:3000,http://127.0.0.1:5500", alias="CORS_ORIGINS"
    )
    rate_limit: str = Field(default="30/minute", alias="RATE_LIMIT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    database_url: str | None = Field(default=None, alias="DATABASE_URL")
    sqlite_path: str = Field(default="data/runs.sqlite3", alias="SQLITE_PATH")

    langsmith_api_key: str | None = Field(default=None, alias="LANGSMITH_API_KEY")
    langchain_tracing_v2: bool = Field(default=False, alias="LANGCHAIN_TRACING_V2")
    langchain_project: str = Field(default="ai-safety-redteam", alias="LANGCHAIN_PROJECT")

    @property
    def cors_origin_list(self) -> list[str]:
        """CORS origins as a list, never containing the wildcard."""
        origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        return [o for o in origins if o != "*"]

    @property
    def llm_enabled(self) -> bool:
        """True when a real Anthropic key is configured."""
        return bool(self.anthropic_api_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings instance."""
    return Settings()
