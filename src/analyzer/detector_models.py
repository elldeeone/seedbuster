"""Detector data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectionResult:
    """Result of phishing detection analysis."""

    domain: str
    score: int
    verdict: str
    reasons: list[str] = field(default_factory=list)
    confidence: float = 0.0

    scam_type: Optional[str] = None

    visual_match_score: float = 0.0
    matched_fingerprint: Optional[str] = None

    seed_form_detected: bool = False
    seed_input_count: int = 0

    suspicious_endpoints: list[str] = field(default_factory=list)

    infrastructure_score: int = 0
    infrastructure_reasons: list[str] = field(default_factory=list)

    code_score: int = 0
    code_reasons: list[str] = field(default_factory=list)
    kit_matches: list[str] = field(default_factory=list)

    temporal_score: int = 0
    temporal_reasons: list[str] = field(default_factory=list)
    cloaking_detected: bool = False

    crypto_doubler_detected: bool = False
    scammer_wallets: list[str] = field(default_factory=list)
