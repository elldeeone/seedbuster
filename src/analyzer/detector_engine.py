"""Phishing detector engine."""

from __future__ import annotations

import io
import logging
from pathlib import Path
from typing import Optional

from PIL import Image
import imagehash

from .browser import BrowserResult
from .code_analysis import CodeAnalyzer
from .detector_content import DetectorContentMixin
from .detector_code import DetectorCodeMixin
from .detector_exploration import DetectorExplorationMixin
from .detector_infrastructure import DetectorInfrastructureMixin
from .detector_models import DetectionResult
from .detector_network import DetectorNetworkMixin
from .detector_rules import (
    CodeRule,
    ContentPatternRule,
    DomainScoreRule,
    EvasionRule,
    ExplorationRule,
    InfrastructureRule,
    NetworkExfilRule,
    SeedFormRule,
    TemporalRule,
    TitleRule,
    VisualMatchRule,
)
from .detector_seed import DetectorSeedMixin
from .detector_visual import DetectorVisualMixin
from .infrastructure import InfrastructureResult
from .metrics import metrics
from .rules import DetectionContext, DetectionRule
from .temporal import TemporalAnalysis
from .threat_intel import ThreatIntelLoader
from .visual_match import VisualMatcher

logger = logging.getLogger(__name__)


class PhishingDetector(
    DetectorVisualMixin,
    DetectorSeedMixin,
    DetectorContentMixin,
    DetectorNetworkMixin,
    DetectorInfrastructureMixin,
    DetectorCodeMixin,
    DetectorExplorationMixin,
):
    """Detects phishing characteristics in analyzed websites."""

    SEED_KEYWORDS = [
        r"recovery\s*phrase",
        r"seed\s*phrase",
        r"mnemonic",
        r"secret\s*phrase",
        r"backup\s*phrase",
        r"12\s*words?",
        r"24\s*words?",
        r"enter\s*(your\s*)?seed",
        r"restore\s*wallet",
        r"import\s*wallet",
        r"recover\s*wallet",
        r"enter\s*mnemonic",
        r"word\s*#?\d+",
        r"recovery\s*words?",
    ]

    DEFAULT_SCORING = {
        "visual_match_high": 40,
        "visual_match_partial": 20,
        "visual_threshold_high": 80,
        "visual_threshold_partial": 60,
        "seed_form_definitive": 50,
        "seed_form_12_24_inputs": 35,
        "seed_form_possible": 25,
        "seed_form_inputs": 15,
        "domain_score_high_threshold": 50,
        "domain_score_high_points": 15,
        "domain_score_medium_threshold": 30,
        "domain_score_medium_points": 10,
        "infra_new_tls": 10,
        "infra_free_short_tls": 5,
        "infra_very_new_domain": 20,
        "infra_new_domain": 10,
        "infra_privacy_dns": 20,
        "infra_bulletproof": 25,
        "code_kit_high_confidence": 30,
        "code_kit_medium_confidence": 15,
        "verdict_high": 70,
        "verdict_medium": 40,
        "verdict_low": 20,
    }

    def __init__(
        self,
        fingerprints_dir: Path,
        config_dir: Optional[Path] = None,
        keywords: list[str] | None = None,
        analysis_threshold: int = 70,
        seed_keywords: list[str] | None = None,
        title_keywords: list[tuple[str, int, str]] | None = None,
        pattern_categories: list[dict] | None = None,
        infrastructure_thresholds: dict | None = None,
        scoring_weights: dict | None = None,
    ):
        self.fingerprints_dir = fingerprints_dir
        self.fingerprints_dir.mkdir(parents=True, exist_ok=True)
        self.keywords = keywords or []
        self.analysis_threshold = analysis_threshold
        self.seed_keywords = seed_keywords or list(self.SEED_KEYWORDS)
        self.title_keywords = title_keywords or [
            ("kaspa", 10, "Kaspa-related title"),
            ("wallet", 5, "Wallet-related title"),
            ("recovery", 10, "Recovery-related title"),
            ("restore", 10, "Restore-related title"),
            ("seed", 10, "Seed-related title"),
            ("claim", 5, "Claim-related title"),
            ("airdrop", 5, "Airdrop-related title"),
        ]
        self.pattern_categories = pattern_categories or []
        self.infrastructure_thresholds = infrastructure_thresholds or {}
        self.scoring = dict(self.DEFAULT_SCORING)
        if scoring_weights:
            self.scoring.update(scoring_weights)

        self._visual_matcher = VisualMatcher(self.fingerprints_dir)

        self.config_dir = config_dir or Path("config")
        self._threat_intel_loader = ThreatIntelLoader(self.config_dir)
        self._threat_intel = self._threat_intel_loader.load()

        self._code_analyzer = CodeAnalyzer(config_dir=self.config_dir)

        self._rules: list[DetectionRule] = [
            VisualMatchRule(),
            SeedFormRule(),
            ContentPatternRule(self.pattern_categories),
        ]

        if self.pattern_categories:
            logger.info(
                "Loaded %s pattern categories: %s",
                len(self.pattern_categories),
                [c.get("name") for c in self.pattern_categories],
            )

        self._rules.extend(
            [
                NetworkExfilRule(),
                DomainScoreRule(),
                TitleRule(),
                EvasionRule(),
                InfrastructureRule(),
                CodeRule(),
                TemporalRule(),
                ExplorationRule(),
            ]
        )

    def reload_threat_intel(self) -> str:
        """Reload threat intelligence from file (hot reload). Returns version."""
        self._threat_intel = self._threat_intel_loader.reload()
        logger.info("Threat intel reloaded: v%s", self._threat_intel.version)
        return self._threat_intel.version

    def save_fingerprint(self, name: str, screenshot: bytes) -> None:
        """Save a fingerprint of a legitimate site."""
        try:
            img = Image.open(io.BytesIO(screenshot))
            phash = imagehash.phash(img)
            fp_path = self.fingerprints_dir / f"{name}.hash"
            fp_path.write_text(str(phash))
            try:
                self._visual_matcher.save_fingerprint_json(
                    name=name,
                    group=name.split("__", 1)[0],
                    variant=None,
                    screenshot=screenshot,
                    html=None,
                )
                self._visual_matcher.reload()
            except Exception as exc:
                logger.debug("Failed to save v2 fingerprint for %s: %s", name, exc)
            logger.info("Saved fingerprint: %s", name)
        except Exception as exc:
            logger.error("Failed to save fingerprint %s: %s", name, exc)

    def detect(
        self,
        browser_result: BrowserResult,
        domain_score: int = 0,
        infrastructure: Optional[InfrastructureResult] = None,
        temporal: Optional[TemporalAnalysis] = None,
    ) -> DetectionResult:
        """Analyze browser results for phishing indicators via rule engine."""
        result = DetectionResult(
            domain=browser_result.domain,
            score=0,
            verdict="low",
            reasons=[],
        )

        if not browser_result.success:
            result.reasons.append(f"Analysis failed: {browser_result.error}")
            return result

        context = DetectionContext(
            browser_result=browser_result,
            domain_score=domain_score,
            infrastructure=infrastructure,
            temporal=temporal,
        )

        total_score = 0
        combined_reasons: list[str] = []
        metadata: dict = {}

        for rule in self._rules:
            try:
                rule_result = rule.apply(self, context)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "Rule %s failed for %s: %s",
                    getattr(rule, "name", "unknown"),
                    browser_result.domain,
                    exc,
                )
                continue

            total_score += rule_result.score
            combined_reasons.extend(rule_result.reasons or [])

            for key, value in (rule_result.metadata or {}).items():
                if value is None:
                    continue
                if isinstance(value, list):
                    existing = metadata.get(key, [])
                    if isinstance(existing, list):
                        metadata[key] = existing + value
                    else:
                        metadata[key] = list(value)
                else:
                    metadata[key] = value

        result.visual_match_score = metadata.get("visual_match_score") or 0.0
        result.matched_fingerprint = metadata.get("matched_fingerprint")
        result.seed_form_detected = bool(metadata.get("seed_form_detected", False))
        result.seed_input_count = int(metadata.get("seed_input_count", 0) or 0)
        result.suspicious_endpoints = metadata.get("suspicious_endpoints", []) or []
        result.infrastructure_score = int(metadata.get("infrastructure_score", 0) or 0)
        result.infrastructure_reasons = metadata.get("infrastructure_reasons", []) or []
        result.code_score = int(metadata.get("code_score", 0) or 0)
        result.code_reasons = metadata.get("code_reasons", []) or []
        result.kit_matches = metadata.get("kit_matches", []) or []
        result.temporal_score = int(metadata.get("temporal_score", 0) or 0)
        result.temporal_reasons = metadata.get("temporal_reasons", []) or []
        result.cloaking_detected = bool(metadata.get("cloaking_detected", False))
        result.crypto_doubler_detected = bool(metadata.get("crypto_doubler_detected", False))
        result.scammer_wallets = metadata.get("scammer_wallets", []) or []

        seed_phishing_detected = bool(metadata.get("seed_phishing_detected", False))

        if metadata.get("scam_type"):
            result.scam_type = metadata.get("scam_type")
        elif result.crypto_doubler_detected:
            result.scam_type = "crypto_doubler"
        elif result.seed_form_detected or seed_phishing_detected:
            result.scam_type = "seed_phishing"

        result.score = min(total_score, 100)
        result.confidence = result.score / 100.0
        result.reasons = combined_reasons

        verdict_high = self.scoring.get("verdict_high", 70)
        verdict_medium = self.scoring.get("verdict_medium", 40)
        verdict_low = self.scoring.get("verdict_low", 20)

        if result.score >= verdict_high:
            result.verdict = "high"
        elif result.score >= verdict_medium:
            result.verdict = "medium"
        elif result.score >= verdict_low:
            result.verdict = "low"
        else:
            result.verdict = "benign"

        metrics.record_verdict(result.verdict)
        if result.scam_type:
            metrics.record_scam_type(result.scam_type)

        return result
