"""FastAPI application exposing the red-team framework.

Endpoints:
    GET  /health         — liveness + configuration snapshot
    POST /api/red-team   — run the corpus against a target, aggregated by OWASP
    GET  /api/runs       — recent persisted runs

Security: CORS restricted to configured origins (never ``*``), slowapi rate
limiting, Pydantic validation returning 422 on bad input.

This module deliberately does not use ``from __future__ import annotations``:
slowapi wraps the endpoints and FastAPI must resolve their real annotation
objects, which string annotations would break.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from ai_safety_framework import __version__
from ai_safety_framework.analyzers.response_analyzer import analyze
from ai_safety_framework.api.schemas import (
    CategoryStatsOut,
    HealthResponse,
    RedTeamRequest,
    RedTeamResponseOut,
    RunSummary,
)
from ai_safety_framework.attacks.corpus import load_corpus
from ai_safety_framework.config import get_settings
from ai_safety_framework.guardrails.layer import default_layer
from ai_safety_framework.observability import configure_logging
from ai_safety_framework.redteam.runner import RedTeamRunner
from ai_safety_framework.schemas import Attack
from ai_safety_framework.storage.repository import get_repository
from ai_safety_framework.targets.http_target import ADAPTERS, HttpTarget

load_dotenv()

limiter = Limiter(key_func=get_remote_address, default_limits=[get_settings().rate_limit])


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Configure logging on startup."""
    configure_logging(get_settings().log_level)
    yield


app = FastAPI(
    title="AI Safety & Red Teaming",
    version=__version__,
    description="OWASP LLM Top 10 attack corpus, guardrails and evaluation.",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

_settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.cors_origin_list,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Return liveness and a snapshot of the active configuration."""
    s = get_settings()
    return HealthResponse(
        status="ok",
        version=__version__,
        model=s.anthropic_model,
        llm_enabled=s.llm_enabled,
        guardrails_enabled=s.enable_guardrails,
        corpus_size=len(load_corpus()),
    )


@app.post("/api/red-team", response_model=RedTeamResponseOut)
@limiter.limit(get_settings().rate_limit)
async def red_team(request: Request, body: RedTeamRequest) -> RedTeamResponseOut:
    """Run the attack corpus against a target and aggregate by OWASP category."""
    if bool(body.target_url) == bool(body.target_text):
        raise HTTPException(422, "provide exactly one of target_url or target_text")

    attacks = _select_attacks(body.categories, body.max_attacks)
    guardrails = default_layer() if body.apply_guardrails else None

    if body.target_text is not None:
        return _analyze_single(attacks, body.target_text, body.apply_guardrails)

    if body.adapter not in ADAPTERS:
        raise HTTPException(422, f"unknown adapter; choose from {sorted(ADAPTERS)}")

    settings = get_settings()
    target = HttpTarget(
        base_url=body.target_url or "",
        adapter=body.adapter,
        timeout_s=settings.target_timeout_s,
        max_retries=settings.target_max_retries,
    )
    try:
        runner = RedTeamRunner(
            target, guardrails=guardrails, max_concurrency=settings.max_concurrency
        )
        report = await runner.run(attacks)
    finally:
        await target.aclose()

    repo = get_repository(settings.database_url, settings.sqlite_path)
    repo.save(report)

    return RedTeamResponseOut(
        run_id=report.run_id,
        target_name=report.target_name,
        guardrails_enabled=report.guardrails_enabled,
        n_attacks=report.n_attacks,
        n_success=report.n_success,
        success_rate=report.success_rate,
        by_category=[
            CategoryStatsOut(
                category=c.category,
                n_attacks=c.n_attacks,
                n_success=c.n_success,
                success_rate=c.success_rate,
            )
            for c in report.by_category.values()
        ],
        latency_ms_total=report.latency_ms_total,
        guardrail_latency_ms_mean=report.guardrail_latency_ms_mean,
    )


@app.get("/api/runs", response_model=list[RunSummary])
async def list_runs(limit: int = 50) -> list[RunSummary]:
    """Return recent persisted runs, newest first."""
    settings = get_settings()
    repo = get_repository(settings.database_url, settings.sqlite_path)
    return [RunSummary(**row) for row in repo.list_runs(limit=limit)]


def _select_attacks(categories: list[str], max_attacks: int) -> list[Attack]:
    """Filter the corpus by category (if given) and cap the count."""
    attacks = load_corpus()
    if categories:
        wanted = set(categories)
        attacks = [a for a in attacks if a.category in wanted]
    if not attacks:
        raise HTTPException(422, "no attacks match the requested categories")
    return attacks[:max_attacks]


def _analyze_single(attacks: list[Attack], text: str, apply_guardrails: bool) -> RedTeamResponseOut:
    """Analyse a single canned response against every selected attack.

    Marks success if the text complies with any attack's malicious intent, and
    reports the category of the first matching attack.
    """
    if apply_guardrails:
        text = default_layer().screen_output(text).sanitized_output
    matched = next((a for a in attacks if analyze(a, text).attack_success), None)
    success = matched is not None
    category = matched.category if matched else attacks[0].category
    return RedTeamResponseOut(
        run_id="single",
        target_name="inline-text",
        guardrails_enabled=apply_guardrails,
        n_attacks=1,
        n_success=int(success),
        success_rate=float(success),
        by_category=[
            CategoryStatsOut(
                category=category,
                n_attacks=1,
                n_success=int(success),
                success_rate=float(success),
            )
        ],
        latency_ms_total=0,
        guardrail_latency_ms_mean=0.0,
    )
