"""Input + output guardrails.

Production: wire `guardrails-ai` or `nvidia-nemo-guardrails`. This module is
dependency-free so it can run in CI.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from src.analyzers.response_analyzer import PII_PATTERNS


SUSPICIOUS_INPUT_PATTERNS: list[tuple[str, str]] = [
    (r"ignore (all )?(previous|prior) (instructions|messages|rules)", "instruction_override"),
    (r"\bDAN\b", "DAN_pattern"),
    (r"system prompt", "system_prompt_probe"),
    (r"<script\b", "html_injection"),
    (r"\bDROP TABLE\b", "sql_injection_payload"),
    (r"\b(?:exec|eval|os\.system|subprocess)", "code_execution_keyword"),
]


@dataclass
class InputGuardrailVerdict:
    safe: bool
    blocked: list[str]


@dataclass
class OutputGuardrailVerdict:
    safe: bool
    redactions: list[str]
    sanitized_output: str


def screen_input(text: str) -> InputGuardrailVerdict:
    matched: list[str] = []
    for pattern, name in SUSPICIOUS_INPUT_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(name)
    return InputGuardrailVerdict(safe=not matched, blocked=matched)


def screen_output(text: str) -> OutputGuardrailVerdict:
    redactions: list[str] = []
    sanitized = text
    for kind, pat in PII_PATTERNS.items():
        new, n = pat.subn(f"[REDACTED:{kind}]", sanitized)
        if n:
            redactions.append(kind)
            sanitized = new
    # Strip script tags
    sanitized = re.sub(r"<script\b[^>]*>.*?</script>", "[REDACTED:script]",
                        sanitized, flags=re.IGNORECASE | re.DOTALL)
    if "[REDACTED:script]" in sanitized:
        redactions.append("html_script")
    return OutputGuardrailVerdict(safe=not redactions, redactions=redactions, sanitized_output=sanitized)
