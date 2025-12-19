"""Rule-based building blocks for phishing detection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol

from .browser import BrowserResult
from .infrastructure import InfrastructureResult
from .temporal import TemporalAnalysis


@dataclass
class DetectionContext:
    """Shared context passed to each detection rule."""

    browser_result: BrowserResult
    domain_score: int
    infrastructure: Optional[InfrastructureResult] = None
    temporal: Optional[TemporalAnalysis] = None


@dataclass
class RuleResult:
    """Outcome of a single detection rule."""

    name: str
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class DetectionRule(Protocol):
    """Interface for detection rules."""

    name: str

    def apply(self, detector, context: DetectionContext) -> RuleResult:  # pragma: no cover - interface
        ...
