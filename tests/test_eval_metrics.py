"""Tests for the eval metrics helpers."""

from __future__ import annotations

from ai_safety_framework.schemas import (
    AttackResult,
    CategoryStats,
    FalsePositiveReport,
    RedTeamReport,
)
from eval.metrics import ablation_layers, pct, render_results_md, worst_cases


def _report(rate: float) -> RedTeamReport:
    results = [
        AttackResult(
            attack_id="A1",
            category="LLM06_info_disclosure",
            technique="pii_fishing",
            severity="critical",
            success=True,
            outcome="complied",
        ),
        AttackResult(
            attack_id="A2",
            category="LLM01_prompt_injection",
            technique="direct_override",
            severity="low",
            success=True,
            outcome="complied",
        ),
    ]
    return RedTeamReport(
        run_id="r",
        target_name="t",
        target_mode="synthetic",
        guardrails_enabled=False,
        n_attacks=2,
        n_success=2,
        success_rate=rate,
        by_category={
            "LLM01_prompt_injection": CategoryStats(
                category="LLM01_prompt_injection",
                n_attacks=1,
                n_success=1,
                n_refused=0,
                n_ignored=0,
                n_error=0,
                success_rate=1.0,
            )
        },
        results=results,
    )


def test_pct_formats() -> None:
    assert pct(0.5) == "50.0%"


def test_ablation_layers_configs() -> None:
    layers = ablation_layers()
    assert set(layers) == {"none", "input_only", "output_only", "full_regex"}
    assert layers["none"] is None


def test_worst_cases_sorted_by_severity() -> None:
    worst = worst_cases(_report(1.0))
    assert worst[0].severity == "critical"


def test_render_results_md_contains_table() -> None:
    fp = FalsePositiveReport(
        run_id="fp",
        target_name="t",
        guardrails_mode="regex",
        n_queries=100,
        n_blocked=1,
        fp_rate=0.01,
    )
    scenarios = [
        {
            "scenario": "Test",
            "target_label": "target",
            "sut_note": "deterministic fallback, no LLM",
            "baseline": _report(0.4).model_dump(mode="json"),
            "guardrailed": _report(0.1).model_dump(mode="json"),
            "fp_report": fp.model_dump(mode="json"),
            "ablation": {"none": 0.4, "full_regex": 0.1},
            "worst_cases": [],
            "llm_status": "pendiente (requiere ANTHROPIC_API_KEY)",
        }
    ]
    md = render_results_md(scenarios)
    assert "Attack success (baseline)" in md
    assert "pendiente (requiere ANTHROPIC_API_KEY)" in md
    assert "LLM01 Prompt Injection" in md
