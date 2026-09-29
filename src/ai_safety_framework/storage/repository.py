"""Run persistence.

Stores each :class:`RedTeamReport` as a JSON document. The default backend is
SQLite (no external service, works everywhere); when ``DATABASE_URL`` is set the
Postgres backend is used with a psycopg connection pool. Both expose the same
tiny interface so the API and eval do not care which is active.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from loguru import logger

from ai_safety_framework.schemas import RedTeamReport


@runtime_checkable
class RunRepository(Protocol):
    """Persist and list red-team run documents."""

    def save(self, report: RedTeamReport) -> None:
        """Persist one report keyed by its ``run_id``."""
        ...

    def list_runs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent run summaries, newest first."""
        ...


class SqliteRepository:
    """SQLite-backed run store (default, dependency-free)."""

    def __init__(self, path: str = "data/runs.sqlite3") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    target_name TEXT NOT NULL,
                    guardrails_enabled INTEGER NOT NULL,
                    success_rate REAL NOT NULL,
                    n_attacks INTEGER NOT NULL,
                    started_at TEXT NOT NULL,
                    document TEXT NOT NULL
                )
                """
            )

    def save(self, report: RedTeamReport) -> None:
        """Insert or replace the run row."""
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    report.run_id,
                    report.target_name,
                    int(report.guardrails_enabled),
                    report.success_rate,
                    report.n_attacks,
                    report.started_at.isoformat(),
                    report.model_dump_json(),
                ),
            )
        logger.info("saved run {} to sqlite", report.run_id)

    def list_runs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent run summaries."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT run_id, target_name, guardrails_enabled, success_rate, "
                "n_attacks, started_at FROM runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


class PostgresRepository:  # pragma: no cover - requires a live database
    """Postgres-backed run store using a psycopg connection pool."""

    def __init__(self, database_url: str) -> None:
        from psycopg_pool import ConnectionPool

        self.pool = ConnectionPool(database_url, min_size=1, max_size=4, open=True)
        self._init_schema()

    def _init_schema(self) -> None:
        with self.pool.connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    target_name TEXT NOT NULL,
                    guardrails_enabled BOOLEAN NOT NULL,
                    success_rate DOUBLE PRECISION NOT NULL,
                    n_attacks INTEGER NOT NULL,
                    started_at TIMESTAMPTZ NOT NULL,
                    document JSONB NOT NULL
                )
                """
            )

    def save(self, report: RedTeamReport) -> None:
        """Upsert the run row."""
        with self.pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO runs VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (run_id) DO UPDATE SET document = EXCLUDED.document
                """,
                (
                    report.run_id,
                    report.target_name,
                    report.guardrails_enabled,
                    report.success_rate,
                    report.n_attacks,
                    report.started_at,
                    json.loads(report.model_dump_json()),
                ),
            )

    def list_runs(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return recent run summaries."""
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT run_id, target_name, guardrails_enabled, success_rate, "
                "n_attacks, started_at FROM runs ORDER BY started_at DESC LIMIT %s",
                (limit,),
            ).fetchall()
        cols = [
            "run_id",
            "target_name",
            "guardrails_enabled",
            "success_rate",
            "n_attacks",
            "started_at",
        ]
        return [dict(zip(cols, r, strict=True)) for r in rows]


def get_repository(database_url: str | None, sqlite_path: str) -> RunRepository:
    """Return a Postgres repo when ``database_url`` is set, else SQLite."""
    if database_url:
        try:
            return PostgresRepository(database_url)
        except Exception as exc:  # pragma: no cover - fall back if DB unreachable
            logger.warning("Postgres unavailable ({}); falling back to SQLite", exc)
    return SqliteRepository(sqlite_path)
