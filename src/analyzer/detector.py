"""Phishing detection logic for SeedBuster."""

import io
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from PIL import Image
import imagehash

from .browser import BrowserResult
from .threat_intel import ThreatIntelLoader
from .infrastructure import InfrastructureResult
from .code_analysis import CodeAnalyzer, CodeAnalysisResult
from .temporal import TemporalAnalysis

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result of phishing detection analysis."""

    domain: str
    score: int
    verdict: str  # "high", "medium", "low", "benign"
    reasons: list[str] = field(default_factory=list)
    confidence: float = 0.0

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

    def __init__(
        self,
        fingerprints_dir: Path,
        config_dir: Optional[Path] = None,
        keywords: list[str] = None,
        analysis_threshold: int = 70,
    ):
        self.fingerprints_dir = fingerprints_dir
        self.fingerprints_dir.mkdir(parents=True, exist_ok=True)
        self.keywords = keywords or []
        self.analysis_threshold = analysis_threshold
        self._fingerprints: dict[str, imagehash.ImageHash] = {}
        self._load_fingerprints()

        # Load threat intelligence
        self.config_dir = config_dir or Path("config")
        self._threat_intel_loader = ThreatIntelLoader(self.config_dir)
        self._threat_intel = self._threat_intel_loader.load()

        # Code analyzer for JS/HTML analysis
        self._code_analyzer = CodeAnalyzer()

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
        """Analyze browser results for phishing indicators."""
        result = DetectionResult(
            domain=browser_result.domain,
            score=0,
            verdict="low",
            reasons=[],
        )

        if not browser_result.success:
            result.reasons.append(f"Analysis failed: {browser_result.error}")
            return result

        # 1. Visual fingerprint comparison
        if browser_result.screenshot:
            visual_score, matched = self._check_visual_match(browser_result.screenshot)
            result.visual_match_score = visual_score
            result.matched_fingerprint = matched

            if visual_score >= 80:
                result.score += 40
                result.reasons.append(f"Visual match to {matched}: {visual_score:.0f}%")
            elif visual_score >= 60:
                result.score += 20
                result.reasons.append(f"Partial visual match to {matched}: {visual_score:.0f}%")

        # 2. Seed phrase form detection
        seed_score, seed_reasons = self._detect_seed_form(browser_result)
        result.score += seed_score
        result.reasons.extend(seed_reasons)
        result.seed_form_detected = seed_score > 0
        result.seed_input_count = self._count_seed_inputs(browser_result)

        # 3. Keyword detection in HTML
        keyword_score, keyword_reasons = self._detect_keywords(browser_result.html or "")
        result.score += keyword_score
        result.reasons.extend(keyword_reasons)

        # 4. Network exfiltration detection
        network_score, network_reasons, endpoints = self._detect_exfiltration(browser_result)
        result.score += network_score
        result.reasons.extend(network_reasons)
        result.suspicious_endpoints = endpoints

        # 5. Add domain score contribution
        if domain_score >= 50:
            result.score += 15
            result.reasons.append(f"High domain suspicion score: {domain_score}")
        elif domain_score >= 30:
            result.score += 10
            result.reasons.append(f"Moderate domain suspicion score: {domain_score}")

        # 6. Suspicious page title/content
        title_score, title_reasons = self._check_title(browser_result.title or "")
        result.score += title_score
        result.reasons.extend(title_reasons)

        # 7. Anti-bot evasion detection
        evasion_score, evasion_reasons = self._detect_evasion(browser_result)
        result.score += evasion_score
        result.reasons.extend(evasion_reasons)

        # 8. Infrastructure intelligence
        if infrastructure:
            infra_score, infra_reasons = self._score_infrastructure(infrastructure)
            result.score += infra_score
            result.infrastructure_score = infra_score
            result.infrastructure_reasons = infra_reasons
            result.reasons.extend(infra_reasons)

        # 9. Code analysis (JS fingerprinting, obfuscation, kit signatures)
        code_result = self._analyze_code(browser_result)
        if code_result.risk_score > 0:
            result.score += code_result.risk_score
            result.code_score = code_result.risk_score
            result.code_reasons = code_result.risk_reasons
            result.kit_matches = [kit.kit_name for kit in code_result.kit_matches]
            result.reasons.extend(code_result.risk_reasons)

        # 10. Temporal analysis (cloaking detection, behavioral patterns)
        if temporal and temporal.temporal_risk_score > 0:
            result.score += temporal.temporal_risk_score
            result.temporal_score = temporal.temporal_risk_score
            result.temporal_reasons = temporal.temporal_reasons
            result.cloaking_detected = temporal.cloaking_detected
            result.reasons.extend(temporal.temporal_reasons)

        # 11. Exploration results (click-through discovered forms)
        if browser_result.explored and browser_result.exploration_steps:
            explore_score, explore_reasons = self._analyze_exploration(browser_result)
            result.score += explore_score
            result.reasons.extend(explore_reasons)

        # Cap and classify
        result.score = min(result.score, 100)
        result.confidence = result.score / 100.0

        if result.score >= 70:
            result.verdict = "high"
        elif result.score >= 40:
            result.verdict = "medium"
        elif result.score >= 20:
            result.verdict = "low"
        else:
            result.verdict = "benign"

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

        # Check exploration steps for seed forms found during click-through
        if result.exploration_steps:
            for step in result.exploration_steps:
                if getattr(step, "is_seed_form", False):
                    score += 50  # High score - definitive evidence
                    reasons.append(f"Seed phrase form found via exploration: '{step.button_text}'")
                    return score, reasons  # This is definitive, no need to check further

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

        # 12 or 24 text inputs is very suspicious
        text_input_count = sum(
            1 for inp in result.input_fields if inp.get("type", "") in ("text", "password", "")
        )

        if text_input_count in (12, 24) or seed_like_inputs >= 10:
            score += 35
            reasons.append(f"Seed phrase form detected ({text_input_count} inputs)")
        elif text_input_count in range(10, 26) and seed_like_inputs >= 3:
            score += 25
            reasons.append(f"Possible seed form ({text_input_count} inputs, {seed_like_inputs} seed-like)")
        elif seed_like_inputs >= 3:
            score += 15
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
        for pattern in self.SEED_KEYWORDS:
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
        suspicious = []
        intel = self._threat_intel

        # Check form submissions to external domains
        for submission in result.form_submissions:
            url = submission.get("url", "")
            if result.domain not in url:
                # Check against threat intel for known malicious
                is_known, indicator = intel.is_known_malicious(url)
                if is_known:
                    score += 50  # Higher score for known bad actors
                    reasons.append(f"KNOWN MALICIOUS: {indicator.value[:50]} ({indicator.confidence})")
                else:
                    score += 30
                    reasons.append(f"Form submits to external: {url[:50]}")
                suspicious.append(url)

                # Check for malicious URL patterns
                pattern_matches = intel.check_malicious_patterns(url)
                for match in pattern_matches:
                    score += 15
                    reasons.append(f"Malicious URL pattern: {match.value}")

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
                suspicious.append(ext)
                reasons.append(f"KNOWN MALICIOUS domain: {indicator.value[:50]}")
                continue

            # Check suspicious hosting patterns from threat intel
            hosting_matches = intel.check_suspicious_hosting(ext)
            for match in hosting_matches:
                score += match.score_modifier
                suspicious.append(ext)
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
                    suspicious.append(indicator.value)
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

        suspicious_titles = [
            ("kaspa", 10, "Kaspa-related title"),
            ("wallet", 5, "Wallet-related title"),
            ("recovery", 10, "Recovery-related title"),
            ("restore", 10, "Restore-related title"),
            ("seed", 10, "Seed-related title"),
            ("claim", 5, "Claim-related title"),
            ("airdrop", 5, "Airdrop-related title"),
        ]

        for keyword, points, reason in suspicious_titles:
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

        # TLS Certificate signals
        if infra.tls:
            # Very new certificates are suspicious
            if infra.tls.is_new:
                score += 10
                reasons.append(f"INFRA: New TLS cert ({infra.tls.age_days} days old)")

            # Free + short-lived is common pattern for phishing
            if infra.tls.is_free_cert and infra.tls.is_short_lived:
                score += 5
                reasons.append(f"INFRA: Free short-lived cert ({infra.tls.issuer})")

        # Domain registration signals
        if infra.domain_info:
            # Very new domains are highly suspicious
            if infra.domain_info.is_very_new:
                score += 20
                reasons.append(f"INFRA: Very new domain ({infra.domain_info.age_days} days)")
            elif infra.domain_info.is_new_domain:
                score += 10
                reasons.append(f"INFRA: New domain ({infra.domain_info.age_days} days)")

            # Privacy-focused DNS is a strong signal
            if infra.domain_info.uses_privacy_dns:
                score += 20
                ns_list = infra.domain_info.nameservers
                ns_sample = ns_list[0] if ns_list else "detected"
                reasons.append(f"INFRA: Privacy DNS (Njalla): {ns_sample}")

        # Hosting signals
        if infra.hosting:
            # Bulletproof hosting is very suspicious
            if infra.hosting.is_bulletproof:
                score += 25
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

            # Check for 12/24 text inputs (seed phrase form pattern)
            text_input_count = sum(
                1 for inp in step.input_fields if inp.get("type", "") in ("text", "password", "")
            )

            if text_input_count in (12, 24) or seed_like_inputs >= 10:
                score += 40
                reasons.append(
                    f"EXPLORE: Seed form found after clicking '{step.button_text}' "
                    f"({text_input_count} inputs)"
                )
            elif text_input_count in range(10, 26) and seed_like_inputs >= 3:
                score += 30
                reasons.append(
                    f"EXPLORE: Possible seed form after '{step.button_text}' "
                    f"({text_input_count} inputs, {seed_like_inputs} seed-like)"
                )
            elif seed_like_inputs >= 3:
                score += 20
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
