"""Target protocol: any system the framework can red-team."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ai_safety_framework.schemas import TargetReply


@runtime_checkable
class Target(Protocol):
    """A system under test.

    Implementations turn one attack prompt into a normalised
    :class:`~ai_safety_framework.schemas.TargetReply`.
    """

    name: str
    mode: str

    async def respond(self, user_message: str) -> TargetReply:
        """Send ``user_message`` to the target and return its reply."""
        ...
