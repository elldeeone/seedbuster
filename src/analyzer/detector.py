"""Phishing detection logic for SeedBuster."""

import io
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from PIL import Image
import imagehash

from .browser import BrowserResult
from .threat_intel import ThreatIntelLoader
from .infrastructure import InfrastructureResult
from .code_analysis import CodeAnalyzer, CodeAnalysisResult
from .temporal import TemporalAnalysis
from .rules import DetectionRule, DetectionContext, RuleResult
from .metrics import metrics

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result of phishing detection analysis."""

    domain: str
    score: int
    verdict: str  # "high", "medium", "low", "benign"
    reasons: list[str] = field(default_factory=list)
    confidence: float = 0.0

    # Scam type classification
    scam_type: Optional[str] = None  # "seed_phishing", "crypto_doubler", "fake_airdrop"

    # Visual analysis
    visual_match_score: float = 0.0
    matched_fingerprint: Optional[str] = None

    # Seed phrase detection
    seed_form_detected: bool = False
    seed_input_count: int = 0

    # Network analysis
    suspicious_endpoints: list[str] = field(default_factory=list)

    # Infrastructure analysis
    infrastructure_score: int = 0
    infrastructure_reasons: list[str] = field(default_factory=list)

    # Code analysis
    code_score: int = 0
    code_reasons: list[str] = field(default_factory=list)
    kit_matches: list[str] = field(default_factory=list)

    # Temporal analysis
    temporal_score: int = 0
    temporal_reasons: list[str] = field(default_factory=list)
    cloaking_detected: bool = False

    # Crypto doubler specific
    crypto_doubler_detected: bool = False
    scammer_wallets: list[str] = field(default_factory=list)


class VisualMatchRule:
    name = "visual_match"

    def apply(self, detector: "PhishingDetector", context: DetectionContext) -> RuleResult:
        score = 0
        reasons: list[str] = []
        metadata: dict = {}
        s = detector.scoring  # Shorthand for scoring weights

        if context.browser_result.screenshot:
            visual_score, matched = detector._check_visual_match(context.browser_result.screenshot)
            metadata["visual_match_score"] = visual_score
            metadata["matched_fingerprint"] = matched

            if visual_score >= s.get("visual_threshold_high", 80):
                score += s.get("visual_match_high", 40)
                reasons.append(f"Visual match to {matched}: {visual_score:.0f}%")
            elif visual_score >= s.get("visual_threshold_partial", 60):
                score += s.get("visual_match_partial", 20)
                reasons.append(f"Partial visual match to {matched}: {visual_score:.0f}%")

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
    """Flexible content pattern detection rule that loads categories from config.

    This replaces hardcoded keyword detection with a config-driven approach.
    Pattern categories are defined in heuristics.yaml and can include any scam type
    (seed_phishing, crypto_doubler, fake_airdrop, etc.) without code changes.
    """

    name = "content_patterns"

    def __init__(self, categories: list[dict] | None = None):
        """Initialize with pattern categories from config.

        Args:
            categories: List of category dicts with keys:
                - name: Category identifier (e.g., "seed_phishing", "crypto_doubler")
                - label: Short label for reasons (e.g., "SEED", "DOUBLER")
                - threshold: Number of matches to flag as this scam type
                - patterns: List of {pattern, points, reason} dicts
        """
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
                    # Record pattern hit for metrics
                    metrics.record_pattern_hit(cat_name, pattern, context.browser_result.domain)

            score += cat_score

            # Check if this category's threshold is met
            if pattern_matches >= cat_threshold:
                detected_types.append(cat_name)
                metadata[f"{cat_name}_detected"] = True
                metrics.record_category_detection(cat_name, context.browser_result.domain)

        # Set primary scam type based on highest-scoring detected type
        if detected_types:
            metadata["scam_type"] = detected_types[0]

        # Also check for wallet addresses (crypto_doubler specific but useful generally)
        if any(cat.get("name") == "crypto_doubler" for cat in self.categories):
            wallets = re.findall(r"kaspa:[a-z0-9]{60,70}", html, re.I)
            unique_wallets = list(set(wallets))
            if unique_wallets:
                metadata["scammer_wallets"] = unique_wallets
                # Check against known scammer wallets
                intel = detector._threat_intel
                for wallet in unique_wallets:
                    for known in getattr(intel, "scammer_wallets", {}).get("kaspa", []):
                        if known.get("address", "").lower() == wallet.lower():
                            score += 50
                            reasons.append(f"DOUBLER: Known scammer wallet: {wallet[:40]}...")
                            break
                    else:
                        # Unknown wallet on a suspicious page with doubler patterns
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


class PhishingDetector:
    """Detects phishing characteristics in analyzed websites."""

    # Keywords that indicate seed phrase phishing
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

    # Default scoring weights
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
        keywords: list[str] = None,
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
        # Merge scoring weights with defaults
        self.scoring = dict(self.DEFAULT_SCORING)
        if scoring_weights:
            self.scoring.update(scoring_weights)

        self._fingerprints: dict[str, imagehash.ImageHash] = {}
        self._load_fingerprints()

        # Load threat intelligence
        self.config_dir = config_dir or Path("config")
        self._threat_intel_loader = ThreatIntelLoader(self.config_dir)
        self._threat_intel = self._threat_intel_loader.load()

        # Code analyzer for JS/HTML analysis (pass config_dir for kit signatures)
        self._code_analyzer = CodeAnalyzer(config_dir=self.config_dir)

        # Build rule list with ContentPatternRule for flexible pattern detection
        self._rules: list[DetectionRule] = [
            VisualMatchRule(),
            SeedFormRule(),
            ContentPatternRule(self.pattern_categories),
        ]

        if self.pattern_categories:
            logger.info(
                f"Loaded {len(self.pattern_categories)} pattern categories: "
                f"{[c.get('name') for c in self.pattern_categories]}"
            )

        self._rules.extend([
            NetworkExfilRule(),
            DomainScoreRule(),
            TitleRule(),
            EvasionRule(),
            InfrastructureRule(),
            CodeRule(),
            TemporalRule(),
            ExplorationRule(),
        ])

    def reload_threat_intel(self) -> str:
        """Reload threat intelligence from file (hot reload). Returns version."""
        self._threat_intel = self._threat_intel_loader.reload()
        logger.info(f"Threat intel reloaded: v{self._threat_intel.version}")
        return self._threat_intel.version

    def _load_fingerprints(self):
        """Load stored fingerprints of legitimate sites."""
        for fp_file in self.fingerprints_dir.glob("*.hash"):
            name = fp_file.stem
            hash_str = fp_file.read_text().strip()
            try:
                self._fingerprints[name] = imagehash.hex_to_hash(hash_str)
                logger.info(f"Loaded fingerprint: {name}")
            except Exception as e:
                logger.error(f"Failed to load fingerprint {name}: {e}")

    def save_fingerprint(self, name: str, screenshot: bytes):
        """Save a fingerprint of a legitimate site."""
        try:
            img = Image.open(io.BytesIO(screenshot))
            phash = imagehash.phash(img)
            fp_path = self.fingerprints_dir / f"{name}.hash"
            fp_path.write_text(str(phash))
            self._fingerprints[name] = phash
            logger.info(f"Saved fingerprint: {name}")
        except Exception as e:
            logger.error(f"Failed to save fingerprint {name}: {e}")

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
                logger.warning("Rule %s failed for %s: %s", getattr(rule, "name", "unknown"), browser_result.domain, exc)
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

        # Apply metadata to result
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

        # Also check for seed_phishing_detected from ContentPatternRule
        seed_phishing_detected = bool(metadata.get("seed_phishing_detected", False))

        # Determine scam type based on detection results
        if metadata.get("scam_type"):
            result.scam_type = metadata.get("scam_type")
        elif result.crypto_doubler_detected:
            result.scam_type = "crypto_doubler"
        elif result.seed_form_detected or seed_phishing_detected:
            result.scam_type = "seed_phishing"

        # Cap and classify using configurable thresholds
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

        # Record metrics
        metrics.record_verdict(result.verdict)
        if result.scam_type:
            metrics.record_scam_type(result.scam_type)

        return result

    def _check_visual_match(self, screenshot: bytes) -> tuple[float, Optional[str]]:
        """Compare screenshot against stored fingerprints."""
        if not self._fingerprints:
            return 0.0, None

        try:
            img = Image.open(io.BytesIO(screenshot))
            current_hash = imagehash.phash(img)

            best_match = None
            best_score = 0.0

            for name, stored_hash in self._fingerprints.items():
                # Calculate similarity (lower difference = more similar)
                diff = current_hash - stored_hash
                # Convert to percentage (hash is 64 bits, max diff is 64)
                similarity = max(0, (64 - diff) / 64 * 100)

                if similarity > best_score:
                    best_score = similarity
                    best_match = name

            return best_score, best_match

        except Exception as e:
            logger.error(f"Error comparing visual fingerprint: {e}")
            return 0.0, None

    def _detect_seed_form(self, result: BrowserResult) -> tuple[int, list[str]]:
        """Detect seed phrase input forms."""
        score = 0
        reasons = []

        # Get configurable thresholds
        s = self.scoring
        exact_counts = s.get("seed_form_exact_counts", [12, 24])
        possible_range = s.get("seed_form_possible_range", [10, 26])
        seed_like_definitive = s.get("seed_like_inputs_definitive", 10)
        seed_like_possible = s.get("seed_like_inputs_possible", 3)

        # Check exploration steps for seed forms found during click-through
        if result.exploration_steps:
            for step in result.exploration_steps:
                if getattr(step, "is_seed_form", False):
                    score += s.get("seed_form_definitive", 50)
                    reasons.append(f"Seed phrase form found via exploration: '{step.button_text}'")
                    return score, reasons  # This is definitive, no need to check further
                # Fallback: 12/24 input pattern discovered via exploration
                text_input_count = sum(
                    1
                    for inp in step.input_fields
                    if (inp.get("type", "") or "").lower() in ("text", "password", "")
                )
                if text_input_count in exact_counts:
                    score += s.get("seed_form_definitive", 50)
                    reasons.append(
                        f"Seed phrase form found via exploration: '{step.button_text}' ({text_input_count} inputs)"
                    )
                    return score, reasons

        # Count text inputs that could be for seed words
        seed_like_inputs = 0
        for inp in result.input_fields:
            inp_type = inp.get("type", "").lower()
            placeholder = inp.get("placeholder", "").lower()
            name = inp.get("name", "").lower()
            inp_id = inp.get("id", "").lower()

            # Check if it looks like a seed word input
            if inp_type in ("text", "password", ""):
                # Check for word-related patterns
                if any(
                    pattern in placeholder + name + inp_id
                    for pattern in ["word", "seed", "mnemonic", "phrase", "recovery"]
                ):
                    seed_like_inputs += 1
                # Check for numbered inputs (word1, word2, etc.)
                elif re.search(r"(word|w|seed|phrase)\s*#?\d+", placeholder + name + inp_id, re.I):
                    seed_like_inputs += 1

        # Count total text inputs
        text_input_count = sum(
            1 for inp in result.input_fields if inp.get("type", "") in ("text", "password", "")
        )

        if text_input_count in exact_counts or seed_like_inputs >= seed_like_definitive:
            score += s.get("seed_form_12_24_inputs", 35)
            reasons.append(f"Seed phrase form detected ({text_input_count} inputs)")
        elif text_input_count in range(possible_range[0], possible_range[1]) and seed_like_inputs >= seed_like_possible:
            score += s.get("seed_form_possible", 25)
            reasons.append(f"Possible seed form ({text_input_count} inputs, {seed_like_inputs} seed-like)")
        elif seed_like_inputs >= seed_like_possible:
            score += s.get("seed_form_inputs", 15)
            reasons.append(f"Seed-related inputs detected ({seed_like_inputs} found)")

        return score, reasons

    def _count_seed_inputs(self, result: BrowserResult) -> int:
        """Count inputs that appear to be for seed words."""
        count = 0
        for inp in result.input_fields:
            if inp.get("type", "") in ("text", "password", ""):
                placeholder = inp.get("placeholder", "").lower()
                name = inp.get("name", "").lower()
                if any(kw in placeholder + name for kw in ["word", "seed", "mnemonic"]):
                    count += 1
        return count

    def _detect_keywords(self, html: str) -> tuple[int, list[str]]:
        """Detect phishing keywords in HTML content."""
        score = 0
        reasons = []
        html_lower = html.lower()

        found_keywords = []
        for pattern in self.seed_keywords:
            if re.search(pattern, html_lower, re.I):
                found_keywords.append(pattern.replace(r"\s*", " ").replace(r"\s+", " "))

        if len(found_keywords) >= 3:
            score += 20
            reasons.append(f"Multiple seed keywords: {', '.join(found_keywords[:5])}")
        elif len(found_keywords) >= 1:
            score += 10
            reasons.append(f"Seed keyword detected: {found_keywords[0]}")

        # Check custom keywords
        for keyword in self.keywords:
            if keyword.lower() in html_lower:
                score += 5
                found_keywords.append(keyword)

        return score, reasons

    def _detect_exfiltration(self, result: BrowserResult) -> tuple[int, list[str], list[str]]:
        """Detect data exfiltration patterns using threat intel."""
        score = 0
        reasons = []
        suspicious: list[str] = []
        seen_suspicious: set[str] = set()
        intel = self._threat_intel
        target_host = ""
        try:
            target_url = result.domain if "://" in result.domain else f"https://{result.domain}"
            target_host = (urlparse(target_url).hostname or "").lower()
        except Exception:
            target_host = ""

        def add_suspicious(value: str) -> None:
            v = (value or "").strip()
            if not v or v in seen_suspicious:
                return
            seen_suspicious.add(v)
            suspicious.append(v)

        # Check form submissions to external domains
        for submission in result.form_submissions:
            url = (submission.get("url") or "").strip()
            if not url:
                continue

            submission_host = ""
            try:
                submission_host = (urlparse(url).hostname or "").lower()
            except Exception:
                submission_host = ""

            # Always check for malicious URL patterns (even if posting to same host).
            pattern_matches = intel.check_malicious_patterns(url)
            for match in pattern_matches:
                score += 15
                reasons.append(f"Malicious URL pattern: {match.value}")
                add_suspicious(url)

            # Only treat as external exfil if hostname differs from the target.
            is_external = False
            if submission_host and target_host:
                is_external = submission_host != target_host
            elif submission_host and not target_host:
                is_external = submission_host not in (result.domain.split("/")[0].lower(), "")
            else:
                # Fallback for odd URLs: best-effort substring check.
                is_external = result.domain not in url

            if not is_external:
                continue

            # Check against threat intel for known malicious
            is_known, indicator = intel.is_known_malicious(url)
            if is_known:
                score += 50  # Higher score for known bad actors
                reasons.append(f"KNOWN MALICIOUS: {indicator.value[:50]} ({indicator.confidence})")
            else:
                score += 30
                reasons.append(f"Form submits to external: {url[:50]}")
            add_suspicious(url)

        # Check external requests against threat intel
        antibot_matches = intel.check_antibot_services(result.external_requests)
        if antibot_matches:
            total_modifier = sum(m.score_modifier for m in antibot_matches)
            score += total_modifier
            services = [m.value for m in antibot_matches[:2]]
            reasons.append(f"Anti-bot detection active: {', '.join(services)}")

        # Check for suspicious hosting
        for ext in result.external_requests:
            ext_lower = ext.lower()

            # Skip common safe CDNs
            if any(safe in ext_lower for safe in [
                "google", "cloudflare", "jsdelivr", "unpkg",
                "cdnjs", "googleapis", "gstatic", "fontawesome"
            ]):
                continue

            # Check against threat intel for known malicious
            is_known, indicator = intel.is_known_malicious(ext)
            if is_known:
                score += 40
                add_suspicious(ext)
                reasons.append(f"KNOWN MALICIOUS domain: {indicator.value[:50]}")
                continue

            # Check suspicious hosting patterns from threat intel
            hosting_matches = intel.check_suspicious_hosting(ext)
            for match in hosting_matches:
                score += match.score_modifier
                add_suspicious(ext)
                reasons.append(f"Suspicious hosting: {ext[:50]}")
                break  # Only count once per domain

        # Check HTML content against threat intel
        if result.html:
            # Check for known malicious API keys in code
            api_key_matches = intel.check_api_keys(result.html)
            for match in api_key_matches:
                score += 50
                reasons.append(f"KNOWN MALICIOUS API key ({match.type}): {match.value[:20]}...")

            # Check for scammer signatures
            sig_matches = intel.check_scammer_signatures(result.html)
            for sig in sig_matches:
                score += 30
                reasons.append(f"Scammer signature: {sig.get('name', 'unknown')}")

            # Check for known malicious domains in code
            for indicator in intel.malicious_domains:
                if indicator.value in result.html:
                    score += 40
                    add_suspicious(indicator.value)
                    reasons.append(f"Malicious endpoint in code: {indicator.value[:50]}")

            # Check for malicious URL patterns in code
            for indicator in intel.malicious_patterns:
                if re.search(indicator.value, result.html, re.I):
                    score += 10
                    reasons.append(f"Exfiltration pattern: {indicator.value}")

            # Fingerprinting detection (static checks)
            fingerprint_indicators = []
            if "toDataURL" in result.html or "getImageData" in result.html:
                fingerprint_indicators.append("canvas")
            if "WEBGL_debug_renderer_info" in result.html or "getParameter(37" in result.html:
                fingerprint_indicators.append("webgl")
            if "AudioContext" in result.html and "createOscillator" in result.html:
                fingerprint_indicators.append("audio")

            if len(fingerprint_indicators) >= 2:
                score += 10
                reasons.append(f"Device fingerprinting: {', '.join(fingerprint_indicators)}")

        return score, reasons, suspicious

    def _check_title(self, title: str) -> tuple[int, list[str]]:
        """Check page title for suspicious patterns."""
        score = 0
        reasons = []
        title_lower = title.lower()

        for keyword, points, reason in self.title_keywords:
            if keyword in title_lower:
                score += points
                reasons.append(reason)

        return score, reasons

    def _detect_evasion(self, result: BrowserResult) -> tuple[int, list[str]]:
        """Detect anti-bot evasion techniques."""
        score = 0
        reasons = []

        # Check if anti-bot services were blocked
        if hasattr(result, 'blocked_requests') and result.blocked_requests:
            score += 15
            blocked_count = len(result.blocked_requests)
            # Extract service names from URLs
            services = set()
            for url in result.blocked_requests:
                try:
                    domain = url.split("/")[2]
                    services.add(domain.split(".")[-2])
                except Exception:
                    pass
            if services:
                reasons.append(f"Anti-bot services blocked: {', '.join(services)} ({blocked_count} requests)")
            else:
                reasons.append(f"Anti-bot services blocked ({blocked_count} requests)")

        # Check if content changed (evasion detected)
        if hasattr(result, 'evasion_detected') and result.evasion_detected:
            score += 20
            if result.title_early and result.title:
                reasons.append(f"Evasion detected: title changed from '{result.title_early[:30]}...' to '{result.title[:30]}...'")
            else:
                reasons.append("Evasion detected: page content changed after load")

        # Check early HTML for seed phrases (in case final page is a cover)
        if hasattr(result, 'html_early') and result.html_early:
            early_keyword_score, early_reasons = self._detect_keywords(result.html_early)
            if early_keyword_score > 0 and hasattr(result, 'evasion_detected') and result.evasion_detected:
                score += early_keyword_score
                for reason in early_reasons:
                    reasons.append(f"[Early capture] {reason}")

        return score, reasons

    def _score_infrastructure(
        self, infra: InfrastructureResult
    ) -> tuple[int, list[str]]:
        """Score infrastructure signals for phishing indicators.

        Infrastructure signals are powerful because they work even when
        the site is cloaked or showing a cover page.
        """
        score = 0
        reasons = []
        s = self.scoring  # Shorthand for scoring weights

        # TLS Certificate signals
        if infra.tls:
            # Very new certificates are suspicious
            if infra.tls.is_new:
                score += s.get("infra_new_tls", 10)
                reasons.append(f"INFRA: New TLS cert ({infra.tls.age_days} days old)")

            # Free + short-lived is common pattern for phishing
            if infra.tls.is_free_cert and infra.tls.is_short_lived:
                score += s.get("infra_free_short_tls", 5)
                reasons.append(f"INFRA: Free short-lived cert ({infra.tls.issuer})")

        # Domain registration signals
        if infra.domain_info:
            # Very new domains are highly suspicious
            if infra.domain_info.is_very_new:
                score += s.get("infra_very_new_domain", 20)
                reasons.append(f"INFRA: Very new domain ({infra.domain_info.age_days} days)")
            elif infra.domain_info.is_new_domain:
                score += s.get("infra_new_domain", 10)
                reasons.append(f"INFRA: New domain ({infra.domain_info.age_days} days)")

            # Privacy-focused DNS is a strong signal
            if infra.domain_info.uses_privacy_dns:
                score += s.get("infra_privacy_dns", 20)
                ns_list = infra.domain_info.nameservers
                ns_sample = ns_list[0] if ns_list else "detected"
                reasons.append(f"INFRA: Privacy DNS (Njalla): {ns_sample}")

        # Hosting signals
        if infra.hosting:
            # Bulletproof hosting is very suspicious
            if infra.hosting.is_bulletproof:
                score += s.get("infra_bulletproof", 25)
                reasons.append(f"INFRA: Bulletproof hosting ({infra.hosting.asn_name})")

        return score, reasons

    def _analyze_code(self, browser_result: BrowserResult) -> CodeAnalysisResult:
        """Analyze HTML/JavaScript for phishing indicators.

        Also incorporates network requests as they may reveal
        malicious endpoints even when the page content is cloaked.
        """
        # Combine HTML sources (early capture may have real content before cloaking)
        html_content = ""
        if browser_result.html:
            html_content += browser_result.html
        if hasattr(browser_result, 'html_early') and browser_result.html_early:
            html_content += "\n" + browser_result.html_early

        # Also include network request URLs as pseudo-code for endpoint detection
        network_urls = ""
        if browser_result.external_requests:
            network_urls = "\n".join(browser_result.external_requests)

        result = self._code_analyzer.analyze(
            domain=browser_result.domain,
            html=html_content,
            javascript=network_urls,  # Network URLs can reveal C2 patterns
        )

        return result

    def _analyze_exploration(self, browser_result: BrowserResult) -> tuple[int, list[str]]:
        """Analyze click-through exploration results for hidden phishing forms.

        This checks what was found when clicking through wallet/recovery buttons.
        """
        score = 0
        reasons = []

        # Get configurable thresholds
        s = self.scoring
        exact_counts = s.get("seed_form_exact_counts", [12, 24])
        possible_range = s.get("seed_form_possible_range", [10, 26])
        seed_like_definitive = s.get("seed_like_inputs_definitive", 10)
        seed_like_possible = s.get("seed_like_inputs_possible", 3)

        for step in browser_result.exploration_steps:
            if not step.success:
                continue

            # Count seed-like inputs found in this step
            seed_like_inputs = 0
            for inp in step.input_fields:
                inp_type = inp.get("type", "").lower()
                placeholder = inp.get("placeholder", "").lower()
                name = inp.get("name", "").lower()
                inp_id = inp.get("id", "").lower()

                combined = placeholder + name + inp_id
                if inp_type in ("text", "password", ""):
                    if any(kw in combined for kw in ["word", "seed", "phrase", "mnemonic", "recovery"]):
                        seed_like_inputs += 1
                    elif re.search(r"(word|w|seed)\s*#?\d+", combined, re.I):
                        seed_like_inputs += 1

            # Check for seed phrase form pattern
            text_input_count = sum(
                1 for inp in step.input_fields if inp.get("type", "") in ("text", "password", "")
            )

            if text_input_count in exact_counts or seed_like_inputs >= seed_like_definitive:
                score += s.get("explore_seed_form", 40)
                reasons.append(
                    f"EXPLORE: Seed form found after clicking '{step.button_text}' "
                    f"({text_input_count} inputs)"
                )
            elif text_input_count in range(possible_range[0], possible_range[1]) and seed_like_inputs >= seed_like_possible:
                score += s.get("explore_possible_seed", 30)
                reasons.append(
                    f"EXPLORE: Possible seed form after '{step.button_text}' "
                    f"({text_input_count} inputs, {seed_like_inputs} seed-like)"
                )
            elif seed_like_inputs >= seed_like_possible:
                score += s.get("explore_seed_inputs", 20)
                reasons.append(
                    f"EXPLORE: Seed inputs after '{step.button_text}' ({seed_like_inputs} found)"
                )

            # Check HTML content from exploration for malicious patterns
            if step.html:
                # Check for exfiltration patterns
                intel = self._threat_intel
                for indicator in intel.malicious_domains:
                    if indicator.value in step.html:
                        score += 35
                        reasons.append(
                            f"EXPLORE: Malicious endpoint found after '{step.button_text}': "
                            f"{indicator.value[:40]}"
                        )

                # Check for known API keys
                api_key_matches = intel.check_api_keys(step.html)
                for match in api_key_matches:
                    score += 30
                    reasons.append(
                        f"EXPLORE: Malicious API key after '{step.button_text}'"
                    )

                # Analyze code in exploration step
                step_code_result = self._code_analyzer.analyze(
                    domain=browser_result.domain,
                    html=step.html,
                )
                if step_code_result.kit_matches:
                    for kit in step_code_result.kit_matches:
                        if kit.confidence >= 0.5:
                            score += 25
                            reasons.append(
                                f"EXPLORE: Kit '{kit.kit_name}' found after '{step.button_text}'"
                            )

        return score, reasons
