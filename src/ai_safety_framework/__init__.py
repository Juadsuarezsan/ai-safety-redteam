"""AI Safety & Red Teaming framework aligned with the OWASP Top 10 for LLM apps.

Public entry points::

    from ai_safety_framework import load_corpus, GuardrailsLayer, RedTeamRunner
"""

from __future__ import annotations

from ai_safety_framework.attacks.corpus import load_corpus, load_legit_queries
from ai_safety_framework.guardrails.layer import GuardrailsLayer, default_layer
from ai_safety_framework.redteam.runner import RedTeamRunner
from ai_safety_framework.schemas import (
    OWASP_CATEGORIES,
    Attack,
    AttackResult,
    FalsePositiveReport,
    LegitQuery,
    RedTeamReport,
)

__version__ = "1.0.0"

__all__ = [
    "OWASP_CATEGORIES",
    "Attack",
    "AttackResult",
    "FalsePositiveReport",
    "GuardrailsLayer",
    "LegitQuery",
    "RedTeamReport",
    "RedTeamRunner",
    "__version__",
    "default_layer",
    "load_corpus",
    "load_legit_queries",
]
