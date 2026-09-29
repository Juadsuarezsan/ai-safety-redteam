"""Input + output guardrails.

The layer screens incoming prompts (blocking known injection/jailbreak patterns)
and sanitises outgoing responses (redacting PII/secrets and neutralising unsafe
HTML). It is dependency-free by default (regex mode); passing extra detectors
enables the ML mode. Both directions are timed so the eval can report the latency
guardrails add.
"""

from __future__ import annotations

from ai_safety_framework.detectors.base import Detector
from ai_safety_framework.detectors.regex_detectors import (
    KeywordInputDetector,
    redact_pii,
    sanitize_html,
)
from ai_safety_framework.observability import timed
from ai_safety_framework.schemas import Detection, InputVerdict, OutputVerdict


class GuardrailsLayer:
    """Input and output guardrails with pluggable detectors.

    Args:
        input_detectors: Detectors run on incoming prompts. A prompt is blocked
            if any of them flags it.
        mode: Label recorded in reports (``regex`` or ``ml``).
    """

    def __init__(
        self,
        input_detectors: list[Detector] | None = None,
        mode: str = "regex",
    ) -> None:
        self.input_detectors: list[Detector] = input_detectors or [KeywordInputDetector()]
        self.mode = mode

    def screen_input(self, text: str) -> InputVerdict:
        """Screen an incoming prompt; unsafe when any detector flags it."""
        with timed() as t:
            detections: list[Detection] = [d.detect(text) for d in self.input_detectors]
            blocked = sorted({label for d in detections if d.flagged for label in d.labels})
        return InputVerdict(
            safe=not blocked,
            blocked=blocked,
            detections=detections,
            latency_ms=t.elapsed_ms,
        )

    def screen_output(self, text: str) -> OutputVerdict:
        """Sanitise an outgoing response (PII redaction + HTML neutralisation)."""
        with timed() as t:
            sanitized, pii_redactions = redact_pii(text)
            sanitized, html_redactions = sanitize_html(sanitized)
            redactions = pii_redactions + html_redactions
        return OutputVerdict(
            safe=not redactions,
            redactions=redactions,
            sanitized_output=sanitized,
            latency_ms=t.elapsed_ms,
        )


def default_layer(mode: str = "regex") -> GuardrailsLayer:
    """Return a guardrails layer with the default regex input detector."""
    return GuardrailsLayer(mode=mode)
