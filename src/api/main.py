"""AI Safety & Red Teaming — placeholder until v0.1.0 build out."""
from __future__ import annotations

from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

load_dotenv()

from src.config import get_settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="AI Safety & Red Teaming",
    version="0.1.0",
    description="AI Safety & Red Teaming — OWASP LLM Top 10 attacks + guardrails",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
async def health() -> dict:
    s = get_settings()
    return {
        "status": "ok",
        "version": "0.1.0",
        "stage": "scaffolding",
        "llm_enabled": "yes" if s.anthropic_api_key else "no",
    }

class AttackRequest(BaseModel):
    target_endpoint: str | None = None
    attack_categories: list[str] = []  # OWASP LLM01..LLM10


class AttackResult(BaseModel):
    category: str
    attack_name: str
    success: bool
    response_snippet: str = ""
    rationale: str = ""


class AttackResponse(BaseModel):
    n_attacks: int = 0
    success_rate: float = 0.0
    by_category: dict[str, float] = {}
    results: list[AttackResult] = []


@app.post("/api/red-team", response_model=AttackResponse)
async def red_team(req: AttackRequest) -> AttackResponse:
    return AttackResponse(n_attacks=0, success_rate=0.0)
