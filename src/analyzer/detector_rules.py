"""Detector rule implementations."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .code_analysis import CodeAnalysisResult
from .metrics import metrics
from .rules import DetectionContext, RuleResult
from .visual_match import VisualMatchResult

if TYPE_CHECKING:
    from .detector_engine import PhishingDetector


class VisualMatchRule:
    name = "visual_match"

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        score = 0
        reasons: list[str] = []
        metadata: dict = {}
        s = detector.scoring

        candidates: list[tuple[bytes, str, str]] = []
        browser = context.browser_result

        if browser.screenshot:
            combined_text = " ".join(
                part for part in [browser.html, browser.title, browser.final_url] if part
            )
            candidates.append((browser.screenshot, combined_text, browser.html or ""))

        if browser.screenshot_early:
            combined_text = " ".join(
                part for part in [browser.html_early, browser.title_early, browser.final_url] if part
            )
            candidates.append((browser.screenshot_early, combined_text, browser.html_early or ""))

        for step in browser.exploration_steps or []:
            if not step.screenshot:
                continue
            combined_text = " ".join(part for part in [step.html, step.title, step.url] if part)
            candidates.append((step.screenshot, combined_text, step.html or ""))

        best_match = VisualMatchResult(0.0, None, None, 0.0, 0.0, 0.0)
        for shot, text, raw_html in candidates:
            match = detector._check_visual_match(shot, text, raw_html)
            if match.score > best_match.score:
                best_match = match

        if best_match.label:
            metadata["visual_match_score"] = best_match.score
            metadata["matched_fingerprint"] = best_match.label
            metadata["visual_match_image_score"] = best_match.image_score
            metadata["visual_match_text_score"] = best_match.text_score
            metadata["visual_match_variant"] = best_match.variant

            if best_match.score >= s.get("visual_threshold_high", 80):
                score += s.get("visual_match_high", 40)
                reasons.append(
                    f"Visual match to {best_match.label}: {best_match.score:.0f}%"
                    f" (image {best_match.image_score:.0f}%, text {best_match.text_score:.0f}%)"
                )
            elif best_match.score >= s.get("visual_threshold_partial", 60):
                score += s.get("visual_match_partial", 20)
                reasons.append(
                    f"Partial visual match to {best_match.label}: {best_match.score:.0f}%"
                    f" (image {best_match.image_score:.0f}%, text {best_match.text_score:.0f}%)"
                )

        return RuleResult(self.name, score=score, reasons=reasons, metadata=metadata)


class SeedFormRule:
    name = "seed_form"

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        score, reasons = detector._detect_seed_form(context.browser_result)
        metadata = {
            "seed_form_detected": score > 0,
            "seed_input_count": detector._count_seed_inputs(context.browser_result),
        }
        return RuleResult(self.name, score=score, reasons=reasons, metadata=metadata)


class ContentPatternRule:
    """Flexible content pattern detection rule that loads categories from config."""

    name = "content_patterns"

    def __init__(self, categories: list[dict] | None = None):
        self.categories = categories or []

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        score = 0
        reasons: list[str] = []
        metadata: dict = {}

        html = context.browser_result.html or ""
        html_lower = html.lower()

        detected_types: list[str] = []

        for category in self.categories:
            cat_name = category.get("name", "unknown")
            cat_label = category.get("label", cat_name.upper())
            cat_threshold = category.get("threshold", 2)
            patterns = category.get("patterns", [])

            pattern_matches = 0
            cat_score = 0

            for p in patterns:
                pattern = p.get("pattern", "")
                points = p.get("points", 10)
                reason = p.get("reason", "Pattern match")

                if not pattern:
                    continue

                if re.search(pattern, html_lower, re.I):
                    cat_score += points
                    pattern_matches += 1
                    reasons.append(f"{cat_label}: {reason}")
                    metrics.record_pattern_hit(cat_name, pattern, context.browser_result.domain)

            score += cat_score

            if pattern_matches >= cat_threshold:
                detected_types.append(cat_name)
                metadata[f"{cat_name}_detected"] = True
                metrics.record_category_detection(cat_name, context.browser_result.domain)

        if detected_types:
            metadata["scam_type"] = detected_types[0]

        if any(cat.get("name") == "crypto_doubler" for cat in self.categories):
            wallets = re.findall(r"kaspa:[a-z0-9]{60,70}", html, re.I)
            unique_wallets = list(set(wallets))
            if unique_wallets:
                metadata["scammer_wallets"] = unique_wallets
                intel = detector._threat_intel
                for wallet in unique_wallets:
                    for known in getattr(intel, "scammer_wallets", {}).get("kaspa", []):
                        if known.get("address", "").lower() == wallet.lower():
                            score += 50
                            reasons.append(f"DOUBLER: Known scammer wallet: {wallet[:40]}...")
                            break
                    else:
                        if metadata.get("crypto_doubler_detected"):
                            score += 20
                            reasons.append(f"DOUBLER: Wallet address found: {wallet[:40]}...")

        return RuleResult(self.name, score=score, reasons=reasons, metadata=metadata)


class NetworkExfilRule:
    name = "network_exfil"

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        score, reasons, endpoints = detector._detect_exfiltration(context.browser_result)
        metadata = {"suspicious_endpoints": endpoints}
        return RuleResult(self.name, score=score, reasons=reasons, metadata=metadata)


class DomainScoreRule:
    name = "domain_score"

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        score = 0
        reasons: list[str] = []
        s = detector.scoring
        domain_score = context.domain_score

        high_threshold = s.get("domain_score_high_threshold", 50)
        high_points = s.get("domain_score_high_points", 15)
        medium_threshold = s.get("domain_score_medium_threshold", 30)
        medium_points = s.get("domain_score_medium_points", 10)

        if domain_score >= high_threshold:
            score += high_points
            reasons.append(f"High domain suspicion score: {domain_score}")
        elif domain_score >= medium_threshold:
            score += medium_points
            reasons.append(f"Moderate domain suspicion score: {domain_score}")
        return RuleResult(self.name, score=score, reasons=reasons)


class TitleRule:
    name = "title_keywords"

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        score, reasons = detector._check_title(context.browser_result.title or "")
        return RuleResult(self.name, score=score, reasons=reasons)


class EvasionRule:
    name = "evasion"

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        score, reasons = detector._detect_evasion(context.browser_result)
        return RuleResult(self.name, score=score, reasons=reasons)


class InfrastructureRule:
    name = "infrastructure"

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        score = 0
        reasons: list[str] = []
        metadata: dict = {}
        if context.infrastructure:
            score, reasons = detector._score_infrastructure(context.infrastructure)
            metadata["infrastructure_score"] = score
            metadata["infrastructure_reasons"] = reasons
        return RuleResult(self.name, score=score, reasons=reasons, metadata=metadata)


class CodeRule:
    name = "code_analysis"

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        code_result: CodeAnalysisResult = detector._analyze_code(context.browser_result)
        if code_result.risk_score <= 0:
            return RuleResult(self.name)

        metadata = {
            "code_score": code_result.risk_score,
            "code_reasons": code_result.risk_reasons,
            "kit_matches": [kit.kit_name for kit in code_result.kit_matches],
        }
        if code_result.c2_endpoints:
            metadata["suspicious_endpoints"] = list(code_result.c2_endpoints)
        return RuleResult(
            self.name,
            score=code_result.risk_score,
            reasons=list(code_result.risk_reasons),
            metadata=metadata,
        )


class TemporalRule:
    name = "temporal"

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        if not context.temporal or context.temporal.temporal_risk_score <= 0:
            return RuleResult(self.name)

        metadata = {
            "temporal_score": context.temporal.temporal_risk_score,
            "temporal_reasons": context.temporal.temporal_reasons,
            "cloaking_detected": context.temporal.cloaking_detected,
        }
        return RuleResult(
            self.name,
            score=context.temporal.temporal_risk_score,
            reasons=list(context.temporal.temporal_reasons),
            metadata=metadata,
        )


class ExplorationRule:
    name = "exploration"

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        if not context.browser_result.exploration_steps:
            return RuleResult(self.name)
        score, reasons = detector._analyze_exploration(context.browser_result)
        return RuleResult(self.name, score=score, reasons=reasons)


__all__ = [
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
