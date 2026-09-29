"""Domain models shared by every layer of the framework.

Everything that crosses a layer boundary (attack corpus -> runner -> analyzer ->
report) is a Pydantic model defined here so that the JSON written to
``eval/runs/`` is the same object the API returns and the PDF renders.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

OwaspCategory = Literal[
    "LLM01_prompt_injection",
    "LLM02_insecure_output",
    "LLM03_training_poison",
    "LLM04_model_dos",
    "LLM05_supply_chain",
    "LLM06_info_disclosure",
    "LLM07_insecure_plugin",
    "LLM08_excessive_agency",
    "LLM09_overreliance",
    "LLM10_model_theft",
]
"""The ten categories of the OWASP Top 10 for LLM Applications (v1.1, 2023)."""

OWASP_CATEGORIES: tuple[OwaspCategory, ...] = (
    "LLM01_prompt_injection",
    "LLM02_insecure_output",
    "LLM03_training_poison",
    "LLM04_model_dos",
    "LLM05_supply_chain",
    "LLM06_info_disclosure",
    "LLM07_insecure_plugin",
    "LLM08_excessive_agency",
    "LLM09_overreliance",
    "LLM10_model_theft",
)

Severity = Literal["critical", "high", "medium", "low"]
Outcome = Literal["refused", "complied", "ignored", "error"]
TargetMode = Literal["synthetic", "deterministic_fallback", "llm"]
AttackSource = Literal["own", "harmbench", "jailbreakbench", "generated", "variant"]


class Attack(BaseModel):
    """One adversarial test case with hand-written ground truth.

    Attributes:
        id: Stable identifier, ``<CATEGORY>-<NNN>`` for the own corpus.
        category: OWASP LLM Top 10 category the attack exercises.
        name: Short human-readable title.
        technique: Attack technique label (``direct_override``, ``base64``, ...).
        prompt: Text sent verbatim to the system under test.
        description: What a vulnerable system would do.
        expected: Safe behaviour. ``refuse`` means the target must decline;
            ``ignore_or_refuse`` accepts an on-task answer that does not comply.
        success_indicators: Lower-case substrings whose presence in a
            non-refusing response marks compliance with the malicious intent.
        max_response_chars: For denial-of-service probes, a response longer
            than this counts as success.
        severity: Business impact if the attack succeeds.
        source: Where the case comes from.
        ground_truth: Provenance of ``expected`` and ``success_indicators``.
    """

    id: str = Field(..., min_length=3, max_length=64)
    category: OwaspCategory
    name: str = Field(..., min_length=1, max_length=120)
    technique: str = Field(..., min_length=1, max_length=64)
    prompt: str = Field(..., min_length=1, max_length=8000)
    description: str = ""
    expected: Literal["refuse", "ignore_or_refuse"] = "refuse"
    success_indicators: list[str] = Field(default_factory=list)
    max_response_chars: int | None = Field(default=None, ge=1)
    severity: Severity = "high"
    source: AttackSource = "own"
    ground_truth: str = "hand-written"


class LegitQuery(BaseModel):
    """A benign request that guardrails must let through (false-positive set)."""

    id: str = Field(..., min_length=3, max_length=64)
    text: str = Field(..., min_length=1, max_length=2000)
    domain: Literal["ecommerce", "sales", "general"]
    tricky: bool = False
    """True when the query contains words that naive blocklists confuse with attacks."""


class TargetReply(BaseModel):
    """Normalised answer from a system under test."""

    text: str
    latency_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    trace_id: str | None = None
    status_code: int | None = None
    mode: TargetMode | None = None


class Detection(BaseModel):
    """Result of one detector over one text."""

    detector: str
    flagged: bool
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    labels: list[str] = Field(default_factory=list)
    details: dict[str, str] = Field(default_factory=dict)


class ResponseAnalysis(BaseModel):
    """Verdict of the response analyzer for one attack/response pair."""

    refused: bool
    complied: bool
    leaked_indicators: list[str] = Field(default_factory=list)
    pii_found: list[str] = Field(default_factory=list)
    denial_of_service: bool = False
    attack_success: bool
    outcome: Outcome
    rationale: str
    detections: list[Detection] = Field(default_factory=list)


class AttackResult(BaseModel):
    """Outcome of one attack against one target, fully instrumented."""

    attack_id: str
    category: OwaspCategory
    technique: str
    severity: Severity
    success: bool
    outcome: Outcome
    refused: bool = False
    leaked_pii: list[str] = Field(default_factory=list)
    flagged_by: list[str] = Field(default_factory=list)
    blocked_by_guardrail: list[str] = Field(default_factory=list)
    output_redactions: list[str] = Field(default_factory=list)
    response_snippet: str = ""
    latency_ms: int = 0
    guardrail_latency_ms: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    trace_id: str = ""
    error: str | None = None
    judge_score: float | None = None


class LegitResult(BaseModel):
    """Outcome of one legitimate query through the guardrails."""

    query_id: str
    domain: str
    tricky: bool
    blocked: bool
    blocked_by: list[str] = Field(default_factory=list)
    refused_by_target: bool = False
    latency_ms: int = 0
    guardrail_latency_ms: int = 0
    response_snippet: str = ""


class CategoryStats(BaseModel):
    """Aggregate for one OWASP category."""

    category: OwaspCategory
    n_attacks: int
    n_success: int
    n_refused: int
    n_ignored: int
    n_error: int
    success_rate: float


class RedTeamReport(BaseModel):
    """Full result of a red-team run against one target configuration."""

    run_id: str
    target_name: str
    target_mode: TargetMode
    guardrails_enabled: bool
    guardrails_mode: str = "none"
    n_attacks: int
    n_success: int
    success_rate: float
    by_category: dict[str, CategoryStats] = Field(default_factory=dict)
    results: list[AttackResult] = Field(default_factory=list)
    latency_ms_total: int = 0
    latency_ms_p50: int = 0
    latency_ms_p95: int = 0
    guardrail_latency_ms_mean: float = 0.0
    cost_usd_total: float = 0.0
    input_tokens_total: int = 0
    output_tokens_total: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    notes: list[str] = Field(default_factory=list)


class FalsePositiveReport(BaseModel):
    """Guardrail false-positive measurement over the legitimate query set."""

    run_id: str
    target_name: str
    guardrails_mode: str
    n_queries: int
    n_blocked: int
    fp_rate: float
    n_refused_by_target: int = 0
    by_domain: dict[str, float] = Field(default_factory=dict)
    tricky_fp_rate: float = 0.0
    guardrail_latency_ms_mean: float = 0.0
    results: list[LegitResult] = Field(default_factory=list)


class InputVerdict(BaseModel):
    """Guardrail decision on an incoming prompt."""

    safe: bool
    blocked: list[str] = Field(default_factory=list)
    detections: list[Detection] = Field(default_factory=list)
    latency_ms: int = 0


class OutputVerdict(BaseModel):
    """Guardrail decision on an outgoing response."""

    safe: bool
    redactions: list[str] = Field(default_factory=list)
    sanitized_output: str
    detections: list[Detection] = Field(default_factory=list)
    latency_ms: int = 0
