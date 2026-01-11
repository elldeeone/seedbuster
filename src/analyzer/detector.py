"""Phishing detection logic for SeedBuster."""

from .detector_engine import PhishingDetector
from .detector_models import DetectionResult
from .detector_rules import (
    VisualMatchRule,
    SeedFormRule,
    ContentPatternRule,
    NetworkExfilRule,
    DomainScoreRule,
    TitleRule,
    EvasionRule,
    InfrastructureRule,
    CodeRule,
    TemporalRule,
    ExplorationRule,
)

__all__ = [
    "DetectionResult",
    "PhishingDetector",
    "VisualMatchRule",
    "SeedFormRule",
    "ContentPatternRule",
    "NetworkExfilRule",
    "DomainScoreRule",
    "TitleRule",
    "EvasionRule",
    "InfrastructureRule",
    "CodeRule",
    "TemporalRule",
    "ExplorationRule",
]
