"""Tests for the command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import respx

from ai_safety_framework.cli import main
from ai_safety_framework.schemas import (
    CategoryStats,
    FalsePositiveReport,
    RedTeamReport,
)


def test_cli_corpus(capsys) -> None:
    assert main(["corpus"]) == 0
    out = capsys.readouterr().out
    assert "OWASP categories" in out


@respx.mock
def test_cli_scan(capsys) -> None:
    respx.post("http://t/api/chat").mock(
        return_value=httpx.Response(200, json={"response": "hello", "mode": "fallback"})
    )
    assert main(["scan", "--url", "http://t", "--adapter", "chat", "--no-guardrails"]) == 0
    assert "success_rate" in capsys.readouterr().out


def test_cli_report(tmp_path: Path, capsys) -> None:
    def _rep(rid: str, rate: float, guarded: bool) -> dict:
        return RedTeamReport(
            run_id=rid,
            target_name="t",
            target_mode="synthetic",
            guardrails_enabled=guarded,
            n_attacks=1,
            n_success=int(rate),
            success_rate=rate,
            by_category={
                "LLM01_prompt_injection": CategoryStats(
                    category="LLM01_prompt_injection",
                    n_attacks=1,
                    n_success=int(rate),
                    n_refused=0,
                    n_ignored=0,
                    n_error=0,
                    success_rate=rate,
                )
            },
        ).model_dump(mode="json")

    fp = FalsePositiveReport(
        run_id="fp",
        target_name="t",
        guardrails_mode="regex",
        n_queries=10,
        n_blocked=0,
        fp_rate=0.0,
    ).model_dump(mode="json")
    scenario = {
        "target_label": "Test",
        "sut_note": "deterministic fallback, no LLM",
        "baseline": _rep("b", 1.0, False),
        "guardrailed": _rep("g", 0.0, True),
        "fp_report": fp,
    }
    scenario_path = tmp_path / "s.json"
    scenario_path.write_text(json.dumps(scenario))
    out_pdf = tmp_path / "r.pdf"
    assert main(["report", str(scenario_path), "-o", str(out_pdf)]) == 0
    assert out_pdf.exists()
