"""Structured logging, trace IDs, token/cost accounting and LangSmith wiring."""

from __future__ import annotations

import math
import sys
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from loguru import logger

from ai_safety_framework.config import PINNED_MODEL, Settings

PRICING_USD_PER_MTOK: dict[str, tuple[float, float]] = {
    PINNED_MODEL: (3.0, 15.0),
    "claude-sonnet-4-5": (3.0, 15.0),
}
"""(input, output) price per million tokens; source: Anthropic public pricing."""

LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | "
    "trace={extra[trace_id]} | <cyan>{name}</cyan>:<cyan>{function}</cyan> - {message}"
)


def configure_logging(level: str = "INFO") -> None:
    """Route loguru to stderr with the trace-aware format."""
    logger.remove()
    logger.configure(extra={"trace_id": "-"})
    logger.add(sys.stderr, level=level.upper(), format=LOG_FORMAT, enqueue=False)


def new_trace_id() -> str:
    """Return a 32-hex-char trace identifier."""
    return uuid.uuid4().hex


def estimate_tokens(text: str) -> int:
    """Rough token estimate (4 chars/token) used when a target reports none."""
    return math.ceil(len(text) / 4) if text else 0


def estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    """Cost of a call from the pricing table; unknown models cost zero."""
    price_in, price_out = PRICING_USD_PER_MTOK.get(model, (0.0, 0.0))
    return round((input_tokens * price_in + output_tokens * price_out) / 1_000_000, 8)


@dataclass
class Timer:
    """Wall-clock timer exposed by :func:`timed`."""

    started: float = field(default_factory=time.perf_counter)
    elapsed_ms: int = 0

    def stop(self) -> int:
        """Freeze and return the elapsed milliseconds."""
        self.elapsed_ms = int((time.perf_counter() - self.started) * 1000)
        return self.elapsed_ms


@contextmanager
def timed() -> Iterator[Timer]:
    """Measure the wall-clock duration of a block in milliseconds."""
    t = Timer()
    try:
        yield t
    finally:
        t.stop()


def langsmith_enabled(settings: Settings) -> bool:
    """True when LangSmith tracing is fully configured through env vars."""
    return settings.langchain_tracing_v2 and bool(settings.langsmith_api_key)


def wrap_anthropic_client(client: Any, settings: Settings) -> Any:
    """Wrap an Anthropic client with LangSmith tracing when configured.

    The ``langsmith`` package is optional (``pip install -e ".[observability]"``);
    without it, or without credentials, the client is returned unchanged.
    """
    if not langsmith_enabled(settings):
        return client
    try:
        from langsmith.wrappers import wrap_anthropic
    except ImportError:
        logger.warning("LangSmith requested but package missing; tracing disabled")
        return client
    logger.info("LangSmith tracing enabled for project {}", settings.langchain_project)
    return wrap_anthropic(client)
