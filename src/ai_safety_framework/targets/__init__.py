"""Systems under test: synthetic targets and the live HTTP adapter."""

from __future__ import annotations

from ai_safety_framework.targets.base import Target
from ai_safety_framework.targets.http_target import ADAPTERS, HttpTarget
from ai_safety_framework.targets.synthetic import GuardrailedTarget, VulnerableTarget

__all__ = [
    "ADAPTERS",
    "GuardrailedTarget",
    "HttpTarget",
    "Target",
    "VulnerableTarget",
]
