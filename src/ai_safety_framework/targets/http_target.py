"""HTTP target adapter.

Sends attack prompts to a live system over HTTP with an explicit timeout and
tenacity retries on transient failures. Two payload/response adapters ship:

* ``chat`` — Project 01 (conversational e-commerce assistant), ``POST /api/chat``
* ``research`` — Project 03 (sales intelligence agent), ``POST /api/research``

The adapter is a pair of pure functions (build request body, extract reply text)
so new targets are one small addition and are unit-testable with mocked HTTP.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import httpx
from loguru import logger
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ai_safety_framework.observability import estimate_tokens, timed
from ai_safety_framework.schemas import TargetMode, TargetReply

RequestBuilder = Callable[[str, str], dict[str, Any]]
ReplyExtractor = Callable[[dict[str, Any]], str]

_RETRYABLE = (httpx.TimeoutException, httpx.TransportError)


class ServerError(Exception):
    """Raised on a 5xx response so tenacity retries it."""


def _chat_request(message: str, session_id: str) -> dict[str, Any]:
    """Build the ``POST /api/chat`` body for Project 01."""
    return {"session_id": session_id, "user_id": "redteam", "message": message}


def _chat_reply(data: dict[str, Any]) -> str:
    """Extract the assistant text from a Project 01 chat response."""
    return str(data.get("response", ""))


def _research_request(message: str, session_id: str) -> dict[str, Any]:
    """Build the ``POST /api/research`` body for Project 03.

    The attack rides in ``seed_context`` (free-text passed into the agent), with a
    fixed benign company so the request validates.
    """
    return {
        "company_name": "Redteam Probe Inc",
        "domain": "redteam-probe.com",
        # seed_context is capped by the target's own validation; truncate so the
        # payload reaches the agent instead of being rejected for length alone.
        "seed_context": message[:1900],
    }


def _research_reply(data: dict[str, Any]) -> str:
    """Flatten a Project 03 research response into inspectable text."""
    email = data.get("email") or {}
    profile = data.get("profile") or {}
    hooks = data.get("hooks") or {}
    parts = [
        str(email.get("subject", "")),
        str(email.get("hook", "")),
        str(email.get("value_prop", "")),
        str(email.get("cta", "")),
        str(profile.get("one_liner", "")),
        str(hooks.get("angle", "")),
    ]
    return "\n".join(p for p in parts if p)


ADAPTERS: dict[str, tuple[str, RequestBuilder, ReplyExtractor]] = {
    "chat": ("/api/chat", _chat_request, _chat_reply),
    "research": ("/api/research", _research_request, _research_reply),
}
"""adapter name -> (path, request builder, reply extractor)."""


def _normalize_mode(raw: object) -> TargetMode:
    """Map a target's own ``mode`` string to a :class:`TargetMode` literal."""
    value = str(raw or "").lower()
    if value == "llm":
        return "llm"
    if value == "synthetic":
        return "synthetic"
    return "deterministic_fallback"


class HttpTarget:
    """A live HTTP system under test.

    Args:
        base_url: Root URL of the target, e.g. ``http://localhost:8001``.
        adapter: Key in :data:`ADAPTERS` selecting request/response shape.
        api_key: Optional bearer token sent as ``Authorization``.
        timeout_s: Per-request timeout in seconds (no infinite default).
        max_retries: Attempts on transient errors (tenacity, exponential backoff).
        name: Human-readable label used in reports.
    """

    def __init__(
        self,
        base_url: str,
        adapter: str = "chat",
        api_key: str | None = None,
        timeout_s: float = 30.0,
        max_retries: int = 3,
        name: str | None = None,
    ) -> None:
        if adapter not in ADAPTERS:
            raise ValueError(f"unknown adapter {adapter!r}; choose from {sorted(ADAPTERS)}")
        self.base_url = base_url.rstrip("/")
        self.adapter = adapter
        self._path, self._build, self._extract = ADAPTERS[adapter]
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.name = name or f"http:{self.base_url}{self._path}"
        self.mode = "deterministic_fallback"
        headers = {"content-type": "application/json"}
        if api_key:
            headers["authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout_s, headers=headers)

    async def respond(self, user_message: str) -> TargetReply:
        """Send one attack prompt and return the normalised reply."""
        session_id = f"rt-{uuid.uuid4().hex[:12]}"
        with timed() as t:
            try:
                data, status = await self._post(user_message, session_id)
            except (*_RETRYABLE, ServerError) as exc:
                logger.warning("target {} failed after retries: {}", self.name, exc)
                return TargetReply(
                    text=f"[target error: {type(exc).__name__}]",
                    latency_ms=t.elapsed_ms,
                    mode="deterministic_fallback",
                )
        if status >= 400:
            # The target rejected the input (e.g. 422 validation, 429 rate limit):
            # a defensive outcome, surfaced as a refusal, not a framework error.
            logger.info("target {} rejected input with HTTP {}", self.name, status)
            return TargetReply(
                text=f"I can't process this request (target returned HTTP {status}).",
                latency_ms=t.elapsed_ms,
                status_code=status,
                mode="deterministic_fallback",
            )
        text = self._extract(data)
        return TargetReply(
            text=text,
            latency_ms=data.get("latency_ms", t.elapsed_ms) or t.elapsed_ms,
            input_tokens=data.get("input_tokens", 0) or estimate_tokens(user_message),
            output_tokens=data.get("output_tokens", 0) or estimate_tokens(text),
            cost_usd=float(data.get("cost_usd", 0.0) or 0.0),
            trace_id=data.get("trace_id"),
            status_code=status,
            mode=_normalize_mode(data.get("mode")),
        )

    @retry(
        retry=retry_if_exception_type((*_RETRYABLE, ServerError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.3, max=4.0),
        reraise=True,
    )
    async def _post(self, message: str, session_id: str) -> tuple[dict[str, Any], int]:
        """POST the attack and return (json body, status).

        5xx responses raise :class:`ServerError` so tenacity retries; 4xx are
        returned to the caller (empty body) as a defensive rejection.
        """
        body = self._build(message, session_id)
        resp = await self._client.post(self._path, json=body)
        if resp.status_code >= 500:
            raise ServerError(f"HTTP {resp.status_code}")
        if resp.status_code >= 400:
            return {}, resp.status_code
        return resp.json(), resp.status_code

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> HttpTarget:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
