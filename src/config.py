from __future__ import annotations
from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-sonnet-4-5", alias="ANTHROPIC_MODEL")
    target_system_url: str = Field(default="http://localhost:8000", alias="TARGET_SYSTEM_URL")
    enable_guardrails: bool = Field(default=True, alias="ENABLE_GUARDRAILS")

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
