"""Code Analysis Engine for SeedBuster.

Analyzes JavaScript and HTML for fingerprinting techniques,
obfuscation patterns, and phishing kit signatures.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


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

    # Known phishing kit signatures
    PHISHING_KIT_SIGNATURES = {
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
        "kaspa_ng_phishing": {
            # Phishing clone of legitimate kaspa-ng.org
            # Key indicators: malicious backend infrastructure + SEO hiding
            "patterns": [
                r"kaspa-backend\.vercel\.app",  # Known C2 notification backend
                r"whale-app.*\.ondigitalocean\.app",  # Known exfil backend
                r"walrus-app.*\.ondigitalocean\.app",  # Known IP logging backend
                r"kaspanet\.one",  # Phishing redirect target
                r"appName.*Kaspa\.ng",  # Kit identity string (domain doesn't exist)
                r"appName.*Kaspa\.one",  # Kit identity string (parked domain)
                r"/api/form/text",  # Exfil endpoint pattern
                r"/api/notification",  # C2 notification pattern
                r"/log-ip",  # IP logging endpoint
            ],
            "html_patterns": [
                r'noindex.*nofollow',  # SEO hiding - legitimate sites don't hide
                r"is_datacenter|is_vpn|is_tor|is_proxy",  # Anti-bot cloaking variables
                r"hasSeenWallet|hasVisited",  # Cloaking state tracking
                r"broswer",  # Typo fingerprint unique to this kit
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
        "metamask_phish": {
            "patterns": [
                r"metamask",
                r"secret.*recovery.*phrase",
                r"12.*word",
            ],
            "html_patterns": [
                r"metamask",
                r"connect.*wallet",
            ],
            "min_matches": 2,
        },
        "trust_wallet_phish": {
            "patterns": [
                r"trustwallet",
                r"trust.*wallet",
                r"recovery.*phrase",
            ],
            "html_patterns": [
                r"trust.*wallet",
                r"import.*wallet",
            ],
            "min_matches": 2,
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

    def __init__(self):
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

        for kit_name, signature in self.PHISHING_KIT_SIGNATURES.items():
            matched_patterns = []

            # Check code patterns
            for pattern_str in signature.get("patterns", []):
                pattern = re.compile(pattern_str, re.IGNORECASE)
                if pattern.search(code):
                    matched_patterns.append(pattern_str)

            # Check HTML patterns
            for pattern_str in signature.get("html_patterns", []):
                pattern = re.compile(pattern_str, re.IGNORECASE)
                if pattern.search(html):
                    matched_patterns.append(f"HTML: {pattern_str}")

            min_matches = signature.get("min_matches", 2)
            if len(matched_patterns) >= min_matches:
                confidence = min(len(matched_patterns) / (min_matches + 2), 1.0)
                matches.append(KitSignatureMatch(
                    kit_name=kit_name,
                    confidence=confidence,
                    matched_patterns=matched_patterns,
                ))

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
) -> CodeAnalysisResult:
    """Analyze code for phishing indicators."""
    analyzer = CodeAnalyzer()
    return analyzer.analyze(domain, html=html, javascript=javascript)
