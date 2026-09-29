"""HTTP request/response models for the API (distinct from domain schemas)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Body of ``GET /health``."""

    status: Literal["ok"]
    version: str
    model: str
    llm_enabled: bool
    guardrails_enabled: bool
    corpus_size: int


class RedTeamRequest(BaseModel):
    """Body of ``POST /api/red-team``.

    Exactly one target must be given: ``target_url`` (a live system) or
    ``target_text`` (analyse a single canned response, no network).
    """

    target_url: str | None = Field(default=None, max_length=2048)
    adapter: Literal["chat", "research"] = "chat"
    target_text: str | None = Field(default=None, max_length=8000)
    categories: list[str] = Field(default_factory=list)
    apply_guardrails: bool = True
    max_attacks: int = Field(default=106, ge=1, le=500)


class CategoryStatsOut(BaseModel):
    """Per-category success stats returned by the API."""

    category: str
    n_attacks: int
    n_success: int
    success_rate: float


class RedTeamResponseOut(BaseModel):
    """Body of ``POST /api/red-team``."""

    run_id: str
    target_name: str
    guardrails_enabled: bool
    n_attacks: int
    n_success: int
    success_rate: float
    by_category: list[CategoryStatsOut]
    latency_ms_total: int
    guardrail_latency_ms_mean: float


class RunSummary(BaseModel):
    """One row of ``GET /api/runs``."""

    run_id: str
    target_name: str
    guardrails_enabled: bool
    success_rate: float
    n_attacks: int
    started_at: str
