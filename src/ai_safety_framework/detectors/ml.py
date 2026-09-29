"""Optional ML detectors behind the :class:`Detector` protocol.

These wrap heavyweight models — DeBERTa prompt-injection, ``unitary/toxic-bert``
and Microsoft Presidio — that live in the ``ml`` optional dependency group
(≈6 GB with CUDA wheels). They are imported **lazily inside the constructor** so
that importing this module never triggers a torch/transformers/presidio import.

In this environment the model weights cannot be downloaded (Hugging Face is
blocked), so the classes are exercised through mocks in the test suite. The
loader is injectable to make that mocking explicit and to let production inject a
warmed pipeline.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from loguru import logger

from ai_safety_framework.schemas import Detection

PROMPT_INJECTION_MODEL = "protectai/deberta-v3-base-prompt-injection"
TOXICITY_MODEL = "unitary/toxic-bert"


class MLDetectorUnavailableError(RuntimeError):
    """Raised when the ``ml`` extra (transformers/torch/presidio) is missing."""


def _load_hf_pipeline(model: str) -> Any:  # pragma: no cover - requires network + torch
    """Build a Hugging Face text-classification pipeline for ``model``.

    Imported lazily; only runs when the ``ml`` extra is installed and weights are
    reachable. Never executed in CI.
    """
    try:
        from transformers import pipeline
    except ImportError as exc:  # pragma: no cover
        raise MLDetectorUnavailableError(
            'ML detectors need the "ml" extra: pip install -e ".[ml]"'
        ) from exc
    logger.info("Loading HF pipeline for {}", model)
    return pipeline("text-classification", model=model, truncation=True)


class PromptInjectionDetector:
    """DeBERTa-based prompt-injection classifier.

    Args:
        threshold: Minimum ``INJECTION`` probability to flag.
        loader: Callable returning a pipeline given a model id. Defaults to the
            real Hugging Face loader; tests inject a fake.
    """

    name = "ml_prompt_injection"

    def __init__(
        self,
        threshold: float = 0.5,
        loader: Callable[[str], Any] = _load_hf_pipeline,
    ) -> None:
        self.threshold = threshold
        self._pipeline = loader(PROMPT_INJECTION_MODEL)

    def detect(self, text: str) -> Detection:
        """Classify ``text`` and flag it when injection probability exceeds the threshold."""
        preds = self._pipeline(text)
        top = preds[0] if isinstance(preds, list) else preds
        label = str(top.get("label", "")).upper()
        score = float(top.get("score", 0.0))
        injection_score = score if label == "INJECTION" else 1.0 - score
        flagged = injection_score >= self.threshold
        return Detection(
            detector=self.name,
            flagged=flagged,
            score=round(injection_score, 4),
            labels=["prompt_injection"] if flagged else [],
            details={"raw_label": label},
        )


class ToxicityDetector:
    """``unitary/toxic-bert`` toxicity classifier."""

    name = "ml_toxicity"

    def __init__(
        self,
        threshold: float = 0.5,
        loader: Callable[[str], Any] = _load_hf_pipeline,
    ) -> None:
        self.threshold = threshold
        self._pipeline = loader(TOXICITY_MODEL)

    def detect(self, text: str) -> Detection:
        """Flag ``text`` when any toxic label exceeds the threshold."""
        preds = self._pipeline(text)
        rows = preds if isinstance(preds, list) else [preds]
        toxic = [r for r in rows if float(r.get("score", 0.0)) >= self.threshold]
        top_score = max((float(r.get("score", 0.0)) for r in rows), default=0.0)
        return Detection(
            detector=self.name,
            flagged=bool(toxic),
            score=round(top_score, 4),
            labels=sorted({str(r.get("label", "")).lower() for r in toxic}),
        )


class PresidioPiiDetector:
    """Microsoft Presidio PII detector (higher recall than the regex baseline)."""

    name = "ml_presidio_pii"

    def __init__(self, analyzer: Any | None = None, score_threshold: float = 0.5) -> None:
        self.score_threshold = score_threshold
        if analyzer is not None:
            self._analyzer = analyzer
        else:  # pragma: no cover - requires presidio + spaCy model
            try:
                from presidio_analyzer import AnalyzerEngine
            except ImportError as exc:  # pragma: no cover
                raise MLDetectorUnavailableError(
                    'Presidio needs the "ml" extra: pip install -e ".[ml]"'
                ) from exc
            self._analyzer = AnalyzerEngine()

    def detect(self, text: str) -> Detection:
        """Return the PII entity types Presidio finds above the threshold."""
        results = self._analyzer.analyze(text=text, language="en")
        kinds = sorted(
            {r.entity_type for r in results if getattr(r, "score", 0.0) >= self.score_threshold}
        )
        return Detection(
            detector=self.name,
            flagged=bool(kinds),
            score=1.0 if kinds else 0.0,
            labels=[k.lower() for k in kinds],
        )
