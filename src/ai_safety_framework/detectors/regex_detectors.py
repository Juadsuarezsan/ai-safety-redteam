"""Dependency-free regex detectors used by the guardrails and analyzer.

These are the always-on baseline. They run in CI without any model download and
serve as the comparison point for the optional ML detectors in :mod:`.ml`.
"""

from __future__ import annotations

import re

from ai_safety_framework.schemas import Detection

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "api_key": re.compile(r"\b(?:sk-ant-[\w-]{10,}|sk-[A-Za-z0-9]{20,})\b"),
    "db_url": re.compile(r"\bpostgres(?:ql)?://[^\s\"']+"),
}
"""Named PII / secret patterns. Recall is limited by design; the ML PII detector
(Presidio) raises recall when the ``ml`` extra is installed."""

# (pattern, label) pairs for suspicious *input*.
INPUT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+(instructions|messages|rules|prompts)",
            re.I,
        ),
        "instruction_override",
    ),
    (
        re.compile(r"\bdisregard\s+(your\s+)?(guidelines|rules|instructions|policy)\b", re.I),
        "instruction_override",
    ),
    (re.compile(r"\bdo\s+anything\s+now\b|\bDAN\b"), "jailbreak_persona"),
    (re.compile(r"\bdeveloper\s+mode\b", re.I), "jailbreak_persona"),
    (re.compile(r"\bunrestricted\s+(assistant|mode)\b", re.I), "jailbreak_persona"),
    (re.compile(r"system\s+prompt|your\s+instructions\s+verbatim", re.I), "system_prompt_probe"),
    (re.compile(r"<\s*script\b|onerror\s*=|onload\s*=|javascript:", re.I), "output_handling_probe"),
    (re.compile(r"\bdrop\s+table\b|;\s*--|\bunion\s+select\b", re.I), "sql_injection"),
    (re.compile(r"\b(?:os\.system|subprocess|eval\(|exec\()", re.I), "code_execution"),
    (re.compile(r"curl\s+[^|]+\|\s*(?:bash|sh)|rm\s+-rf\s+/", re.I), "remote_exec"),
    (
        re.compile(r"pip\s+install\s+https?://|https?://\S+\.(?:tar\.gz|whl|bin|pem|sh)\b", re.I),
        "supply_chain",
    ),
    (
        re.compile(
            r"(?:ANTHROPIC_API_KEY|DATABASE_URL|env\b).*(?:print|show|reveal|value|paste|dump)",
            re.I,
        ),
        "secret_probe",
    ),
    (
        re.compile(
            r"(?:print|show|reveal|paste|dump).*(?:ANTHROPIC_API_KEY|DATABASE_URL|environment\s+variable)",
            re.I,
        ),
        "secret_probe",
    ),
    (
        re.compile(
            r"remember\s+this\s+(permanently|forever|for\s+all)|save\s+this\s+rule|update\s+your\s+memory",
            re.I,
        ),
        "memory_poison",
    ),
    (re.compile(r"<\|?(system|im_start|im_end)\|?>", re.I), "control_token_spoof"),
]

# Encoded-payload heuristics (base64/rot13 carriers).
_B64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


class KeywordInputDetector:
    """Flag prompts matching any known injection/jailbreak pattern."""

    name = "regex_input"

    def detect(self, text: str) -> Detection:
        """Return a detection listing every matched attack pattern label."""
        labels = sorted({label for pat, label in INPUT_PATTERNS if pat.search(text)})
        if _looks_like_encoded_command(text):
            labels.append("encoded_payload")
            labels = sorted(set(labels))
        flagged = bool(labels)
        return Detection(
            detector=self.name,
            flagged=flagged,
            score=1.0 if flagged else 0.0,
            labels=labels,
        )


class PiiDetector:
    """Flag PII/secret patterns in a text (used on outputs)."""

    name = "regex_pii"

    def detect(self, text: str) -> Detection:
        """Return a detection listing every PII/secret kind found."""
        found = sorted({kind for kind, pat in PII_PATTERNS.items() if pat.search(text)})
        return Detection(
            detector=self.name,
            flagged=bool(found),
            score=1.0 if found else 0.0,
            labels=found,
        )


def _looks_like_encoded_command(text: str) -> bool:
    """Heuristic: a long base64 blob next to a 'decode/execute/follow' verb."""
    lowered = text.lower()
    has_verb = any(v in lowered for v in ("decode", "base64", "rot13", "execute", "follow"))
    return has_verb and bool(_B64.search(text))


def redact_pii(text: str) -> tuple[str, list[str]]:
    """Replace every PII/secret match with ``[REDACTED:<kind>]``.

    Returns the sanitized text and the list of redacted kinds.
    """
    redactions: list[str] = []
    sanitized = text
    for kind, pat in PII_PATTERNS.items():
        sanitized, n = pat.subn(f"[REDACTED:{kind}]", sanitized)
        if n:
            redactions.append(kind)
    return sanitized, redactions


_SCRIPT = re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.I | re.S)
_EVENT_HANDLER = re.compile(r"\son\w+\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I)
_JS_URI = re.compile(r"(href|src)\s*=\s*(\"|')?\s*javascript:[^\"'>\s]*", re.I)
_DANGEROUS_TAG = re.compile(r"<\s*(iframe|object|embed|svg)\b[^>]*>", re.I)


def sanitize_html(text: str) -> tuple[str, list[str]]:
    """Neutralise script tags, event handlers and dangerous URIs/tags.

    Returns the sanitized text and the labels of the sanitisations applied.
    """
    redactions: list[str] = []
    sanitized = text
    if _SCRIPT.search(sanitized):
        sanitized = _SCRIPT.sub("[REDACTED:script]", sanitized)
        redactions.append("html_script")
    if _JS_URI.search(sanitized):
        sanitized = _JS_URI.sub(r"\1=[REDACTED:js_uri]", sanitized)
        redactions.append("js_uri")
    if _EVENT_HANDLER.search(sanitized):
        sanitized = _EVENT_HANDLER.sub(" [REDACTED:event_handler]", sanitized)
        redactions.append("event_handler")
    if _DANGEROUS_TAG.search(sanitized):
        sanitized = _DANGEROUS_TAG.sub("[REDACTED:tag]", sanitized)
        redactions.append("dangerous_tag")
    return sanitized, redactions
