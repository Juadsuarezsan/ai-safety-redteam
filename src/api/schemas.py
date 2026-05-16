from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

OwaspCategory = Literal[
    "LLM01_prompt_injection", "LLM02_insecure_output", "LLM03_training_poison",
    "LLM04_model_dos", "LLM05_supply_chain", "LLM06_info_disclosure",
    "LLM07_insecure_plugin", "LLM08_excessive_agency", "LLM09_overreliance",
    "LLM10_model_theft",
]


class Attack(BaseModel):
    id: str
    category: OwaspCategory
    name: str
    prompt: str
    description: str = ""


class AttackResult(BaseModel):
    attack_id: str
    category: OwaspCategory
    success: bool
    response_snippet: str = ""
    refused: bool = False
    leaked_pii: list[str] = Field(default_factory=list)
    flagged_by: list[str] = Field(default_factory=list)


class RedTeamRequest(BaseModel):
    target_endpoint: str | None = None
    target_text: str | None = None       # If you want to test a single response
    attack_ids: list[str] = Field(default_factory=list)
    apply_guardrails: bool = True


class RedTeamResponse(BaseModel):
    n_attacks: int
    success_rate: float
    by_category: dict[str, float] = Field(default_factory=dict)
    results: list[AttackResult] = Field(default_factory=list)
    guardrails_applied: bool = False
    latency_ms: int = 0
