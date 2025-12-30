"""Code Analysis Engine for SeedBuster.

Analyzes JavaScript and HTML for fingerprinting techniques,
obfuscation patterns, and phishing kit signatures.
"""

import logging
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


def load_kit_signatures(config_dir: Path | None = None) -> dict:
    """Load phishing kit signatures from config file."""
    config_dir = config_dir or Path("config")
    path = config_dir / "kit_signatures.yaml"

    if not path.exists():
        logger.warning(f"Kit signatures config not found: {path}")
        return {}

    try:
        data = yaml.safe_load(path.read_text()) or {}
        signatures = data.get("kit_signatures", {})
        logger.info(f"Loaded {len(signatures)} kit signatures from config")
        return signatures
    except Exception as e:
        logger.error(f"Failed to load kit signatures: {e}")
        return {}


@dataclass
class FingerprintingResult:
    """Results of fingerprinting technique detection."""

    techniques_found: list[str] = field(default_factory=list)
    antibot_checks: list[str] = field(default_factory=list)
    evasion_code: list[str] = field(default_factory=list)
    score: int = 0


@dataclass
class ObfuscationResult:
    """Results of obfuscation detection."""

    is_obfuscated: bool = False
    obfuscation_type: str = ""
    confidence: float = 0.0
    indicators: list[str] = field(default_factory=list)
    score: int = 0


@dataclass
class KitSignatureMatch:
    """A matched phishing kit signature."""

    kit_name: str
    version: str = ""
    confidence: float = 0.0
    matched_patterns: list[str] = field(default_factory=list)


@dataclass
class CodeAnalysisResult:
    """Complete code analysis result."""

    domain: str
    fingerprinting: FingerprintingResult = field(default_factory=FingerprintingResult)
    obfuscation: ObfuscationResult = field(default_factory=ObfuscationResult)
    kit_matches: list[KitSignatureMatch] = field(default_factory=list)

    # Extracted intelligence
    c2_endpoints: list[str] = field(default_factory=list)
    api_keys_found: list[str] = field(default_factory=list)
    suspicious_functions: list[str] = field(default_factory=list)

    # Scoring
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)

    def calculate_risk_score(self) -> tuple[int, list[str]]:
        """Calculate code analysis risk score."""
        score = 0
        reasons = []

        # Fingerprinting signals
        if self.fingerprinting.techniques_found:
            fp_score = min(len(self.fingerprinting.techniques_found) * 5, 20)
            score += fp_score
            reasons.append(
                f"CODE: {len(self.fingerprinting.techniques_found)} fingerprinting techniques"
            )

        if self.fingerprinting.antibot_checks:
            score += 15
            reasons.append(
                f"CODE: Anti-bot detection ({', '.join(self.fingerprinting.antibot_checks[:2])})"
            )

        # Obfuscation signals
        if self.obfuscation.is_obfuscated:
            score += 15
            reasons.append(f"CODE: Obfuscated JS ({self.obfuscation.obfuscation_type})")

        # Kit matches
        for kit in self.kit_matches:
            if kit.confidence >= 0.8:
                score += 30
                reasons.append(f"CODE: Known phishing kit '{kit.kit_name}' ({kit.confidence:.0%})")
            elif kit.confidence >= 0.5:
                score += 15
                reasons.append(f"CODE: Possible kit '{kit.kit_name}' ({kit.confidence:.0%})")

        # C2 endpoints
        if self.c2_endpoints:
            score += 10
            reasons.append(f"CODE: {len(self.c2_endpoints)} suspicious endpoints extracted")

        # Suspicious functions
        if self.suspicious_functions:
            score += min(len(self.suspicious_functions) * 5, 15)
            reasons.append(
                f"CODE: Suspicious functions ({', '.join(self.suspicious_functions[:3])})"
            )

        self.risk_score = score
        self.risk_reasons = reasons
        return score, reasons


class CodeAnalyzer:
    """Analyzes JavaScript and HTML for phishing indicators."""

    # Browser fingerprinting patterns
    FINGERPRINT_PATTERNS = {
        "webdriver": [
            r"navigator\.webdriver",
            r"navigator\[.webdriver.\]",
            r"window\.navigator\.webdriver",
        ],
        "canvas": [
            r"\.toDataURL\s*\(",
            r"canvas\.getContext\s*\(\s*['\"]2d['\"]\s*\)",
            r"getImageData\s*\(",
        ],
        "webgl": [
            r"getContext\s*\(\s*['\"]webgl['\"]\s*\)",
            r"getContext\s*\(\s*['\"]experimental-webgl['\"]\s*\)",
            r"WEBGL_debug_renderer_info",
            r"UNMASKED_VENDOR_WEBGL",
            r"UNMASKED_RENDERER_WEBGL",
        ],
        "audio": [
            r"AudioContext",
            r"OfflineAudioContext",
            r"createOscillator",
            r"createDynamicsCompressor",
        ],
        "fonts": [
            r"measureText\s*\(",
            r"font-family.*sans-serif",
            r"document\.fonts",
        ],
        "screen": [
            r"screen\.width",
            r"screen\.height",
            r"screen\.colorDepth",
            r"screen\.pixelDepth",
            r"window\.devicePixelRatio",
        ],
        "timezone": [
            r"getTimezoneOffset\s*\(",
            r"Intl\.DateTimeFormat",
            r"timeZone",
        ],
        "plugins": [
            r"navigator\.plugins",
            r"navigator\.mimeTypes",
        ],
        "hardware": [
            r"navigator\.hardwareConcurrency",
            r"navigator\.deviceMemory",
            r"navigator\.maxTouchPoints",
        ],
    }

    # Anti-bot detection patterns
    ANTIBOT_PATTERNS = {
        "webdriver_check": [
            r"if\s*\(\s*navigator\.webdriver\s*\)",
            r"navigator\.webdriver\s*===?\s*true",
            r"window\.chrome\s*&&\s*window\.chrome\.runtime",
        ],
        "phantom_check": [
            r"window\._phantom",
            r"window\.callPhantom",
            r"phantom",
        ],
        "selenium_check": [
            r"document\.\$cdc",
            r"document\.\$wdc",
            r"\$cdc_",
            r"selenium",
        ],
        "headless_check": [
            r"HeadlessChrome",
            r"navigator\.languages\.length\s*===?\s*0",
            r"!window\.chrome",
        ],
        "devtools_check": [
            r"devtools",
            r"__REACT_DEVTOOLS",
            r"firebug",
        ],
    }

    # Obfuscation indicators
    OBFUSCATION_PATTERNS = {
        "eval_based": [
            r"eval\s*\(\s*['\"]",
            r"eval\s*\(\s*atob",
            r"eval\s*\(\s*String\.fromCharCode",
            r"new\s+Function\s*\(",
        ],
        "hex_strings": [
            r"\\x[0-9a-fA-F]{2}",
            r"0x[0-9a-fA-F]+",
        ],
        "unicode_escape": [
            r"\\u[0-9a-fA-F]{4}",
        ],
        "base64": [
            r"atob\s*\(",
            r"btoa\s*\(",
        ],
        "array_notation": [
            r"\[['\"]\w+['\"]\]\s*\(",  # obj["method"]()
            r"window\s*\[\s*['\"]",
        ],
        "string_splitting": [
            r"['\"].*['\"]\.split\s*\(\s*['\"]['\"]",
            r"\.join\s*\(\s*['\"]['\"]",
            r"\.reverse\s*\(\s*\)\.join",
        ],
    }

    # Default phishing kit signatures (used if config file not found)
    DEFAULT_KIT_SIGNATURES = {
        "kaspa_stealer_v1": {
            "patterns": [
                r"ondigitalocean\.app",
                r"/api/form/submit",
                r"/log-ip",
                r"seed.*phrase.*input",
            ],
            "html_patterns": [
                r"kaspa.*wallet",
                r"enter.*your.*seed",
                r"recovery.*phrase",
            ],
            "min_matches": 2,
        },
        "generic_seed_stealer": {
            "patterns": [
                r"mnemonic",
                r"seed.*phrase",
                r"recovery.*words?",
                r"word\s*#?\d+",
            ],
            "html_patterns": [
                r"<input[^>]*type=['\"]text['\"][^>]*>.*seed",
                r"wallet.*restore",
                r"import.*wallet",
            ],
            "min_matches": 3,
        },
    }

    # Suspicious function patterns
    SUSPICIOUS_FUNCTIONS = {
        "data_exfil": [
            r"fetch\s*\(\s*['\"]https?://[^'\"]+",
            r"XMLHttpRequest",
            r"\.send\s*\(",
            r"navigator\.sendBeacon",
        ],
        "form_capture": [
            r"addEventListener\s*\(\s*['\"]submit['\"]",
            r"\.value\s*[=;]",
            r"FormData",
            r"serializeArray",
        ],
        "clipboard": [
            r"navigator\.clipboard",
            r"execCommand\s*\(\s*['\"]copy['\"]",
            r"clipboardData",
        ],
        "keylogger": [
            r"addEventListener\s*\(\s*['\"]keydown['\"]",
            r"addEventListener\s*\(\s*['\"]keyup['\"]",
            r"addEventListener\s*\(\s*['\"]keypress['\"]",
            r"onkeydown",
            r"onkeyup",
        ],
        "storage_access": [
            r"localStorage",
            r"sessionStorage",
            r"indexedDB",
        ],
    }

    def __init__(self, config_dir: Path | None = None):
        """Initialize code analyzer.

        Args:
            config_dir: Path to config directory. If provided, kit signatures
                        are loaded from config/kit_signatures.yaml.
        """
        self.config_dir = config_dir
        # Load kit signatures from config or use defaults
        self._kit_signatures = load_kit_signatures(config_dir) if config_dir else {}
        if not self._kit_signatures:
            self._kit_signatures = self.DEFAULT_KIT_SIGNATURES
            logger.info("Using default kit signatures (no config loaded)")
        else:
            logger.info(f"Loaded {len(self._kit_signatures)} kit signatures from config")

        # Compile regex patterns for efficiency
        self._compiled_patterns = {}
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile all regex patterns."""
        for category, patterns in self.FINGERPRINT_PATTERNS.items():
            self._compiled_patterns[f"fp_{category}"] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        for category, patterns in self.ANTIBOT_PATTERNS.items():
            self._compiled_patterns[f"ab_{category}"] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        for category, patterns in self.OBFUSCATION_PATTERNS.items():
            self._compiled_patterns[f"ob_{category}"] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

        for category, patterns in self.SUSPICIOUS_FUNCTIONS.items():
            self._compiled_patterns[f"sf_{category}"] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def analyze(
        self,
        domain: str,
        html: Optional[str] = None,
        javascript: Optional[str] = None,
        scripts: Optional[list[str]] = None,
    ) -> CodeAnalysisResult:
        """Perform complete code analysis."""
        result = CodeAnalysisResult(domain=domain)

        # Combine all code for analysis
        all_code = ""
        if html:
            all_code += html + "\n"
            # Extract inline scripts
            inline_scripts = self._extract_inline_scripts(html)
            all_code += "\n".join(inline_scripts)

        if javascript:
            all_code += javascript + "\n"

        if scripts:
            all_code += "\n".join(scripts)

        if not all_code.strip():
            return result

        # Run analyses
        result.fingerprinting = self._detect_fingerprinting(all_code)
        result.obfuscation = self._detect_obfuscation(all_code)
        result.kit_matches = self._match_kit_signatures(all_code, html or "")
        result.c2_endpoints = self._extract_c2_endpoints(all_code)
        result.api_keys_found = self._extract_api_keys(all_code)
        result.suspicious_functions = self._detect_suspicious_functions(all_code)

        # Calculate risk score
        result.calculate_risk_score()

        return result

    def _extract_inline_scripts(self, html: str) -> list[str]:
        """Extract inline JavaScript from HTML."""
        scripts = []
        pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
        for match in pattern.finditer(html):
            script_content = match.group(1).strip()
            if script_content:
                scripts.append(script_content)
        return scripts

    def _extract_asset_urls(self, html: str) -> list[str]:
        """Extract asset URLs from HTML (best-effort)."""
        if not html:
            return []
        urls = []
        for match in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
            url = match.group(1).strip()
            if not url or url.startswith('data:'):
                continue
            urls.append(url)
        return urls


    def _detect_fingerprinting(self, code: str) -> FingerprintingResult:
        """Detect browser fingerprinting techniques."""
        result = FingerprintingResult()

        # Check fingerprinting techniques
        for category in self.FINGERPRINT_PATTERNS.keys():
            patterns = self._compiled_patterns.get(f"fp_{category}", [])
            for pattern in patterns:
                if pattern.search(code):
                    if category not in result.techniques_found:
                        result.techniques_found.append(category)
                    break

        # Check anti-bot detection
        for category in self.ANTIBOT_PATTERNS.keys():
            patterns = self._compiled_patterns.get(f"ab_{category}", [])
            for pattern in patterns:
                if pattern.search(code):
                    if category not in result.antibot_checks:
                        result.antibot_checks.append(category)
                    break

        # Calculate score
        result.score = (
            len(result.techniques_found) * 5 +
            len(result.antibot_checks) * 10
        )

        return result

    def _detect_obfuscation(self, code: str) -> ObfuscationResult:
        """Detect code obfuscation."""
        result = ObfuscationResult()

        indicators_found = []
        obfuscation_types = []

        for category, patterns_key in [
            ("eval_based", "ob_eval_based"),
            ("hex_strings", "ob_hex_strings"),
            ("unicode_escape", "ob_unicode_escape"),
            ("base64", "ob_base64"),
            ("array_notation", "ob_array_notation"),
            ("string_splitting", "ob_string_splitting"),
        ]:
            patterns = self._compiled_patterns.get(patterns_key, [])
            for pattern in patterns:
                matches = pattern.findall(code)
                if matches:
                    indicators_found.append(category)
                    obfuscation_types.append(category)
                    break

        # Check for high entropy (sign of obfuscation)
        if self._check_high_entropy(code):
            indicators_found.append("high_entropy")

        # Check for very long lines (common in obfuscated code)
        if self._check_long_lines(code):
            indicators_found.append("long_lines")

        # Determine if obfuscated
        if len(indicators_found) >= 3:
            result.is_obfuscated = True
            result.confidence = min(len(indicators_found) * 0.15, 1.0)
            result.obfuscation_type = ", ".join(obfuscation_types[:3])
        elif len(indicators_found) >= 2:
            result.is_obfuscated = True
            result.confidence = 0.5
            result.obfuscation_type = ", ".join(obfuscation_types[:2])

        result.indicators = indicators_found
        result.score = 15 if result.is_obfuscated else 0

        return result

    def _check_high_entropy(self, code: str) -> bool:
        """Check if code has unusually high entropy (sign of obfuscation)."""
        if len(code) < 1000:
            return False

        # Sample the code
        sample = code[:5000]

        # Count character frequencies
        freq = {}
        for char in sample:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        import math
        entropy = 0
        for count in freq.values():
            p = count / len(sample)
            entropy -= p * math.log2(p)

        # High entropy indicates obfuscation (typical code is 4-5, obfuscated is 5.5+)
        return entropy > 5.5

    def _check_long_lines(self, code: str) -> bool:
        """Check for very long lines (common in minified/obfuscated code)."""
        lines = code.split("\n")
        long_lines = sum(1 for line in lines if len(line) > 1000)
        return long_lines >= 1

    def _match_kit_signatures(self, code: str, html: str) -> list[KitSignatureMatch]:
        """Match against known phishing kit signatures."""
        matches = []

        asset_urls = self._extract_asset_urls(html)
        asset_text = "\n".join(asset_urls)
        asset_hashes = {hashlib.sha256(url.encode()).hexdigest() for url in asset_urls}

        def _collect(patterns: list[str], haystack: str, *, prefix: str = "", kit_name: str = "") -> list[str]:
            matched = []
            for pattern_str in patterns:
                try:
                    pattern = re.compile(pattern_str, re.IGNORECASE)
                except re.error as exc:
                    logger.warning(
                        "Invalid kit signature regex for %s: %s (%s)",
                        kit_name,
                        pattern_str,
                        exc,
                    )
                    continue
                if pattern.search(haystack):
                    matched.append(f"{prefix}{pattern_str}" if prefix else pattern_str)
            return matched

        def _collect_hashes(expected_hashes: list[str]) -> list[str]:
            matched = []
            for expected in expected_hashes:
                raw = (expected or "").strip()
                if not raw:
                    continue
                if raw.startswith("sha256:"):
                    raw = raw.split(":", 1)[1]
                if raw in asset_hashes:
                    matched.append(f"ASSET_HASH: {expected}")
            return matched

        for kit_name, signature in self._kit_signatures.items():
            signal_groups = signature.get("signal_groups")
            if signal_groups:
                total_score = 0
                group_hits = 0
                matched_patterns = []
                failed_required = False

                for group in signal_groups:
                    group_matches = []
                    group_matches.extend(
                        _collect(group.get("patterns", []), code, kit_name=kit_name)
                    )
                    group_matches.extend(
                        _collect(
                            group.get("html_patterns", []),
                            html,
                            prefix="HTML: ",
                            kit_name=kit_name,
                        )
                    )
                    group_matches.extend(
                        _collect(
                            group.get("dom_patterns", []),
                            html,
                            prefix="DOM: ",
                            kit_name=kit_name,
                        )
                    )
                    group_matches.extend(
                        _collect(
                            group.get("asset_patterns", []),
                            asset_text,
                            prefix="ASSET: ",
                            kit_name=kit_name,
                        )
                    )
                    group_matches.extend(
                        _collect_hashes(group.get("asset_hashes", []))
                    )

                    seen_group = set()
                    group_deduped = []
                    for item in group_matches:
                        if item in seen_group:
                            continue
                        group_deduped.append(item)
                        seen_group.add(item)

                    min_matches = group.get("min_matches", 1)
                    if group.get("required") and len(group_deduped) < min_matches:
                        failed_required = True
                        break

                    if len(group_deduped) >= min_matches:
                        total_score += int(group.get("weight", 1))
                        group_hits += 1

                    matched_patterns.extend(group_deduped)

                if failed_required:
                    continue

                seen = set()
                deduped = []
                for item in matched_patterns:
                    if item in seen:
                        continue
                    deduped.append(item)
                    seen.add(item)

                min_score = signature.get("min_score")
                if min_score is None:
                    min_score = max(
                        1,
                        sum(int(g.get("weight", 1)) for g in signal_groups),
                    )
                min_groups = signature.get("min_groups", 1)

                if total_score >= min_score and group_hits >= min_groups:
                    confidence = min(total_score / (min_score + 1), 1.0)
                    matches.append(
                        KitSignatureMatch(
                            kit_name=kit_name,
                            confidence=confidence,
                            matched_patterns=deduped,
                        )
                    )
                continue

            matched_patterns = []
            required_patterns = signature.get("required_patterns", [])
            required_html_patterns = signature.get("required_html_patterns", [])

            required_hits = _collect(required_patterns, code, kit_name=kit_name)
            required_html_hits = _collect(
                required_html_patterns,
                html,
                prefix="HTML: ",
                kit_name=kit_name,
            )

            if required_patterns and not required_hits:
                continue
            if required_html_patterns and not required_html_hits:
                continue

            matched_patterns.extend(_collect(signature.get("patterns", []), code, kit_name=kit_name))
            matched_patterns.extend(
                _collect(signature.get("html_patterns", []), html, prefix="HTML: ", kit_name=kit_name)
            )
            matched_patterns.extend(required_hits)
            matched_patterns.extend(required_html_hits)

            seen = set()
            deduped = []
            for item in matched_patterns:
                if item in seen:
                    continue
                deduped.append(item)
                seen.add(item)

            min_matches = signature.get("min_matches", 2)
            if len(deduped) >= min_matches:
                confidence = min(len(deduped) / (min_matches + 2), 1.0)
                matches.append(
                    KitSignatureMatch(
                        kit_name=kit_name,
                        confidence=confidence,
                        matched_patterns=deduped,
                    )
                )

        return matches


    def _extract_c2_endpoints(self, code: str) -> list[str]:
        """Extract potential C2/backend endpoints from code."""
        endpoints = set()

        # URL patterns
        url_patterns = [
            r'https?://[^\s\'"<>]+',
            r'fetch\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'\.open\s*\(\s*[\'"][A-Z]+[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]',
            r'action\s*=\s*[\'"]([^\'"]+)[\'"]',
        ]

        for pattern_str in url_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for match in pattern.finditer(code):
                url = match.group(1) if match.lastindex else match.group(0)
                # Filter out common legitimate URLs
                if self._is_suspicious_endpoint(url):
                    endpoints.add(url)

        return list(endpoints)[:20]  # Limit to 20

    def _is_suspicious_endpoint(self, url: str) -> bool:
        """Check if an endpoint looks suspicious."""
        # Skip common legitimate domains
        legitimate = [
            "google.com", "googleapis.com", "gstatic.com",
            "cloudflare.com", "cloudfront.net",
            "jquery.com", "jsdelivr.net", "unpkg.com",
            "facebook.com", "twitter.com",
            "bootstrap", "fontawesome",
        ]

        url_lower = url.lower()
        for legit in legitimate:
            if legit in url_lower:
                return False

        # Check for suspicious patterns
        suspicious_patterns = [
            r"ondigitalocean\.app",
            r"herokuapp\.com",
            r"netlify\.app",
            r"vercel\.app",
            r"ngrok",
            r"/api/",
            r"/submit",
            r"/log",
            r"/collect",
            r"/track",
            r"/exfil",
            r"\.php\?",
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, url_lower):
                return True

        return False

    def _extract_api_keys(self, code: str) -> list[str]:
        """Extract potential API keys from code."""
        keys = []

        # API key patterns
        patterns = [
            r'api[_-]?key[\'"\s:=]+([a-zA-Z0-9_-]{20,})',
            r'apikey[\'"\s:=]+([a-zA-Z0-9_-]{20,})',
            r'secret[\'"\s:=]+([a-zA-Z0-9_-]{20,})',
            r'token[\'"\s:=]+([a-zA-Z0-9_-]{20,})',
        ]

        for pattern_str in patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            for match in pattern.finditer(code):
                key = match.group(1)
                # Don't include obvious placeholders
                if not key.lower().startswith(("xxx", "your", "insert", "replace")):
                    keys.append(key[:30] + "...")  # Truncate for safety

        return keys[:10]  # Limit to 10

    def _detect_suspicious_functions(self, code: str) -> list[str]:
        """Detect suspicious function usage."""
        found = []

        for category in self.SUSPICIOUS_FUNCTIONS.keys():
            patterns = self._compiled_patterns.get(f"sf_{category}", [])
            for pattern in patterns:
                if pattern.search(code):
                    if category not in found:
                        found.append(category)
                    break

        return found


# Convenience function
def analyze_code(
    domain: str,
    html: Optional[str] = None,
    javascript: Optional[str] = None,
    config_dir: Path | None = None,
) -> CodeAnalysisResult:
    """Analyze code for phishing indicators."""
    analyzer = CodeAnalyzer(config_dir=config_dir)
    return analyzer.analyze(domain, html=html, javascript=javascript)
