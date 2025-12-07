"""Phishing detection logic for SeedBuster."""

import hashlib
import io
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from PIL import Image
import imagehash

from .browser import BrowserResult

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
        keywords: list[str] = None,
        analysis_threshold: int = 70,
    ):
        self.fingerprints_dir = fingerprints_dir
        self.fingerprints_dir.mkdir(parents=True, exist_ok=True)
        self.keywords = keywords or []
        self.analysis_threshold = analysis_threshold
        self._fingerprints: dict[str, imagehash.ImageHash] = {}
        self._load_fingerprints()

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

    def detect(self, browser_result: BrowserResult, domain_score: int = 0) -> DetectionResult:
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
        """Detect data exfiltration patterns."""
        score = 0
        reasons = []
        suspicious = []

        # Check form submissions to external domains
        for submission in result.form_submissions:
            url = submission.get("url", "")
            if result.domain not in url:
                score += 30
                suspicious.append(url)
                reasons.append(f"Form submits to external: {url[:50]}")

        # Check for suspicious external requests
        for ext in result.external_requests:
            # Skip common CDNs and analytics
            if any(
                safe in ext
                for safe in [
                    "google",
                    "cloudflare",
                    "jsdelivr",
                    "unpkg",
                    "cdnjs",
                    "googleapis",
                ]
            ):
                continue

            # Flag unknown data collectors
            if any(
                sus in ext.lower()
                for sus in ["collect", "track", "log", "api", "webhook", "telegram"]
            ):
                score += 10
                suspicious.append(ext)
                reasons.append(f"Suspicious endpoint: {ext[:50]}")

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
