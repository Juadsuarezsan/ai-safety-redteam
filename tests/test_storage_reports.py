"""Tests for the SQLite run store and PDF report generation."""

from __future__ import annotations

from pathlib import Path

from ai_safety_framework.reports.pdf import generate_pdf_report
from ai_safety_framework.schemas import (
    CategoryStats,
    FalsePositiveReport,
    RedTeamReport,
)
from ai_safety_framework.storage.repository import SqliteRepository, get_repository


def _report(run_id: str, rate: float, guarded: bool) -> RedTeamReport:
    return RedTeamReport(
        run_id=run_id,
        target_name="t",
        target_mode="synthetic",
        guardrails_enabled=guarded,
        n_attacks=10,
        n_success=int(rate * 10),
        success_rate=rate,
        by_category={
            "LLM01_prompt_injection": CategoryStats(
                category="LLM01_prompt_injection",
                n_attacks=10,
                n_success=int(rate * 10),
                n_refused=0,
                n_ignored=0,
                n_error=0,
                success_rate=rate,
            )
        },
    )


def test_sqlite_save_and_list(tmp_path: Path) -> None:
    repo = SqliteRepository(str(tmp_path / "runs.sqlite3"))
    repo.save(_report("r1", 0.5, False))
    repo.save(_report("r2", 0.1, True))
    rows = repo.list_runs()
    assert len(rows) == 2
    assert {r["run_id"] for r in rows} == {"r1", "r2"}


def test_sqlite_upsert_replaces(tmp_path: Path) -> None:
    repo = SqliteRepository(str(tmp_path / "runs.sqlite3"))
    repo.save(_report("r1", 0.5, False))
    repo.save(_report("r1", 0.2, False))
    rows = repo.list_runs()
    assert len(rows) == 1
    assert rows[0]["success_rate"] == 0.2


def test_get_repository_defaults_to_sqlite(tmp_path: Path) -> None:
    repo = get_repository(None, str(tmp_path / "x.sqlite3"))
    assert isinstance(repo, SqliteRepository)


def test_pdf_report_is_written(tmp_path: Path) -> None:
    fp = FalsePositiveReport(
        run_id="fp",
        target_name="t",
        guardrails_mode="regex",
        n_queries=100,
        n_blocked=2,
        fp_rate=0.02,
    )
    out = generate_pdf_report(
        baseline=_report("base", 0.4, False),
        guardrailed=_report("guard", 0.1, True),
        fp_report=fp,
        output_path=str(tmp_path / "report.pdf"),
        target_label="Test target",
        system_under_test_note="deterministic fallback, no LLM",
    )
    assert out.exists()
    assert out.read_bytes().startswith(b"%PDF")
