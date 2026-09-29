"""Detector protocol.

A detector inspects one piece of text (an incoming prompt or an outgoing
response) and returns a :class:`~ai_safety_framework.schemas.Detection`. Regex
detectors ship in :mod:`.regex_detectors`; heavyweight ML detectors live in
:mod:`.ml` behind the same protocol and are imported lazily so the base install
never pulls in torch/transformers/presidio.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ai_safety_framework.schemas import Detection


@runtime_checkable
class Detector(Protocol):
    """A single text detector.

    Implementations must be pure and side-effect free so they can run in any
    order and be unit tested without external services.
    """

    name: str

    def detect(self, text: str) -> Detection:
        """Inspect ``text`` and return a :class:`Detection`."""
        ...
