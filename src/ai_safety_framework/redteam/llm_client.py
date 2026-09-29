"""Anthropic client behind a Protocol.

The real client uses the official ``anthropic`` SDK with an explicit timeout and
tenacity retries on transient errors. It is **never** called in tests or in the
offline eval — a real ``ANTHROPIC_API_KEY`` is required, so those paths inject a
fake implementing :class:`LlmClient`.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ai_safety_framework.config import Settings
from ai_safety_framework.observability import estimate_cost_usd
from ai_safety_framework.schemas import TargetReply


@runtime_checkable
class LlmClient(Protocol):
    """Minimal chat interface the red-teamer and judge depend on."""

    async def complete(self, system: str, user: str, max_tokens: int = 1024) -> TargetReply:
        """Return the model's reply to a (system, user) message pair."""
        ...


class AnthropicClient:
    """Real Anthropic client. Requires a configured API key.

    Args:
        settings: Runtime settings carrying the key, model and timeout.
    """

    def __init__(self, settings: Settings) -> None:
        if not settings.anthropic_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is required for the real LLM client")
        self.settings = settings
        from anthropic import AsyncAnthropic  # lazy: keep import cost out of offline paths

        self._client = AsyncAnthropic(
            api_key=settings.anthropic_api_key,
            timeout=settings.anthropic_timeout_s,
            max_retries=0,  # retries handled by tenacity below
        )

    @retry(
        retry=retry_if_exception_type(Exception),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, max=8.0),
        reraise=True,
    )
    async def complete(
        self, system: str, user: str, max_tokens: int = 1024
    ) -> TargetReply:  # pragma: no cover - requires ANTHROPIC_API_KEY
        """Call the Messages API and return the reply with token/cost accounting."""
        resp = await self._client.messages.create(
            model=self.settings.anthropic_model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(block.text for block in resp.content if block.type == "text")
        usage_in = resp.usage.input_tokens
        usage_out = resp.usage.output_tokens
        return TargetReply(
            text=text,
            input_tokens=usage_in,
            output_tokens=usage_out,
            cost_usd=estimate_cost_usd(self.settings.anthropic_model, usage_in, usage_out),
            mode="llm",
        )
