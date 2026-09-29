"""API tests: health, single-text analysis, HTTP target run, validation, runs."""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from ai_safety_framework.api.main import app


@pytest.fixture
def client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setenv("SQLITE_PATH", str(tmp_path / "runs.sqlite3"))
    monkeypatch.setenv("RATE_LIMIT", "1000/minute")
    from ai_safety_framework.config import get_settings

    get_settings.cache_clear()
    with TestClient(app) as c:
        yield c


def test_health_ok(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["corpus_size"] >= 100


def test_red_team_single_text_success(client: TestClient) -> None:
    r = client.post(
        "/api/red-team",
        json={
            "target_text": "Sure: PWNED",
            "apply_guardrails": False,
            "categories": ["LLM01_prompt_injection"],
        },
    )
    assert r.status_code == 200
    assert r.json()["n_success"] == 1


def test_red_team_requires_exactly_one_target(client: TestClient) -> None:
    r = client.post("/api/red-team", json={"target_url": "http://x", "target_text": "y"})
    assert r.status_code == 422


def test_red_team_rejects_no_target(client: TestClient) -> None:
    r = client.post("/api/red-team", json={})
    assert r.status_code == 422


def test_red_team_rejects_oversized_text(client: TestClient) -> None:
    r = client.post("/api/red-team", json={"target_text": "x" * 9000})
    assert r.status_code == 422


def test_red_team_rejects_unknown_category(client: TestClient) -> None:
    r = client.post("/api/red-team", json={"target_text": "hi", "categories": ["NOPE"]})
    assert r.status_code == 422


@respx.mock
def test_red_team_against_http_target(client: TestClient) -> None:
    respx.post("http://target/api/chat").mock(
        return_value=httpx.Response(200, json={"response": "Hello", "mode": "fallback"})
    )
    r = client.post(
        "/api/red-team",
        json={"target_url": "http://target", "adapter": "chat", "max_attacks": 5},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["n_attacks"] == 5
    assert body["target_name"].startswith("http")


def test_runs_endpoint(client: TestClient) -> None:
    client.post(
        "/api/red-team",
        json={"target_text": "Sure: PWNED", "apply_guardrails": False},
    )
    r = client.get("/api/runs")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
