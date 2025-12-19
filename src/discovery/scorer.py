"""Domain scoring for phishing detection."""

import unicodedata
from dataclasses import dataclass
from typing import Set

import idna
import tldextract
from rapidfuzz import fuzz


@dataclass
class ScoringResult:
    """Result of domain scoring."""

    domain: str
    score: int
    reasons: list[str]
    min_score_to_analyze: int = 30
    is_allowlisted: bool = False
    is_denylisted: bool = False

    @property
    def should_analyze(self) -> bool:
        """Whether this domain should proceed to analysis."""
        return not self.is_allowlisted and (self.is_denylisted or self.score >= self.min_score_to_analyze)


class DomainScorer:
    """Scores domains for phishing likelihood based on various heuristics."""

    # Cyrillic characters that look like Latin
    HOMOGLYPHS = {
        "а": "a",  # Cyrillic а
        "е": "e",  # Cyrillic е
        "о": "o",  # Cyrillic о
        "р": "p",  # Cyrillic р
        "с": "c",  # Cyrillic с
        "у": "y",  # Cyrillic у
        "х": "x",  # Cyrillic х
        "ѕ": "s",  # Cyrillic ѕ
        "і": "i",  # Cyrillic і
        "ј": "j",  # Cyrillic ј
        "ԁ": "d",  # Cyrillic ԁ
        "ɡ": "g",  # Latin script g
        "ո": "n",  # Armenian ո
        "ս": "u",  # Armenian ս
    }

    def __init__(
        self,
        target_patterns: list[str],
        allowlist: Set[str],
        denylist: Set[str],
        suspicious_tlds: Set[str],
        min_score_to_analyze: int = 30,
        keyword_weights: list[tuple[str, int]] | None = None,
        substitutions: dict[str, str] | None = None,
    ):
        self.target_patterns = [p.lower() for p in target_patterns]
        self.allowlist = {d.lower() for d in allowlist}
        self.denylist = {d.lower() for d in denylist}
        self.suspicious_tlds = {t.lower() for t in suspicious_tlds}
        self.min_score_to_analyze = min_score_to_analyze
        self.keyword_weights = keyword_weights or [
            ("wallet", 10),
            ("recover", 15),
            ("seed", 15),
            ("restore", 10),
            ("login", 5),
            ("secure", 5),
            ("official", 10),
            ("verify", 10),
            ("claim", 10),
            ("airdrop", 10),
        ]
        self.substitutions = substitutions or {
            "4": "a",
            "3": "e",
            "1": "i",
            "0": "o",
            "5": "s",
            "@": "a",
            "$": "s",
        }

    def score_domain(self, domain: str) -> ScoringResult:
        """Score a domain for phishing likelihood."""
        domain = domain.lower().strip()
        reasons = []
        score = 0

        # Extract domain parts
        extracted = tldextract.extract(domain)
        registered_domain = f"{extracted.domain}.{extracted.suffix}"
        full_domain = domain

        # Check allowlist (exact match on registered domain)
        if registered_domain in self.allowlist or full_domain in self.allowlist:
            return ScoringResult(
                domain=domain,
                score=0,
                reasons=["Allowlisted"],
                min_score_to_analyze=self.min_score_to_analyze,
                is_allowlisted=True,
            )

        # Check denylist
        if registered_domain in self.denylist or full_domain in self.denylist:
            return ScoringResult(
                domain=domain,
                score=100,
                reasons=["Denylisted - known malicious"],
                min_score_to_analyze=self.min_score_to_analyze,
                is_denylisted=True,
            )

        # Check for IDN/homograph attacks
        idn_score, idn_reasons = self._check_idn_homograph(domain)
        score += idn_score
        reasons.extend(idn_reasons)

        # Check fuzzy match against target patterns
        fuzzy_score, fuzzy_reasons = self._check_fuzzy_match(extracted.domain)
        score += fuzzy_score
        reasons.extend(fuzzy_reasons)

        # Check suspicious TLD
        if extracted.suffix.lower() in self.suspicious_tlds:
            score += 15
            reasons.append(f"Suspicious TLD: .{extracted.suffix}")

        # Check for suspicious keywords in subdomain/path
        keyword_score, keyword_reasons = self._check_keywords(full_domain)
        score += keyword_score
        reasons.extend(keyword_reasons)

        # Check for number substitutions (k4spa, kasp4, etc.)
        subst_score, subst_reasons = self._check_substitutions(extracted.domain)
        score += subst_score
        reasons.extend(subst_reasons)

        # Cap score at 100
        score = min(score, 100)

        return ScoringResult(
            domain=domain,
            score=score,
            reasons=reasons,
            min_score_to_analyze=self.min_score_to_analyze,
        )

    def _check_idn_homograph(self, domain: str) -> tuple[int, list[str]]:
        """Check for IDN homograph attacks."""
        score = 0
        reasons = []

        # CT feeds and browsers often represent IDNs as ASCII punycode (xn--...).
        # Decode to Unicode when possible so homoglyph checks work in practice.
        candidate = domain
        try:
            if "xn--" in domain:
                decoded = idna.decode(domain)
                if decoded and decoded != domain:
                    candidate = decoded
        except Exception:
            candidate = domain

        try:
            # Check if domain contains non-ASCII characters
            if not candidate.isascii():
                # Validate that it is IDNA-encodable
                idna.encode(candidate)

                # Check if it contains homoglyphs
                normalized = self._normalize_homoglyphs(candidate)
                for pattern in self.target_patterns:
                    if pattern in normalized.lower():
                        score += 40
                        reasons.append(f"IDN homograph attack detected: looks like '{pattern}'")
                        break
        except (idna.IDNAError, UnicodeError):
            pass

        return score, reasons

    def _normalize_homoglyphs(self, text: str) -> str:
        """Replace homoglyphs with their Latin equivalents."""
        result = []
        for char in text:
            if char in self.HOMOGLYPHS:
                result.append(self.HOMOGLYPHS[char])
            else:
                # Try NFKC normalization for other lookalikes
                normalized = unicodedata.normalize("NFKC", char)
                result.append(normalized)
        return "".join(result)

    def _check_fuzzy_match(self, domain_name: str) -> tuple[int, list[str]]:
        """Check fuzzy similarity to target patterns."""
        score = 0
        reasons = []

        for pattern in self.target_patterns:
            # Exact match (shouldn't happen if allowlisted correctly)
            if pattern == domain_name:
                continue

            # Check if pattern is contained in domain
            if pattern in domain_name:
                score += 30
                reasons.append(f"Contains target pattern: '{pattern}'")
                continue

            # Fuzzy match using Levenshtein distance
            ratio = fuzz.ratio(pattern, domain_name)
            if ratio >= 85:
                score += 35
                reasons.append(f"Very similar to '{pattern}' ({ratio}% match)")
            elif ratio >= 70:
                score += 20
                reasons.append(f"Similar to '{pattern}' ({ratio}% match)")

            # Check for partial matches (e.g., "kaspa-wallet" contains "kaspa")
            partial = fuzz.partial_ratio(pattern, domain_name)
            if partial >= 90 and partial > ratio:
                score += 15
                reasons.append(f"Partial match to '{pattern}' ({partial}%)")

        return score, reasons

    def _check_keywords(self, domain: str) -> tuple[int, list[str]]:
        """Check for suspicious keywords."""
        score = 0
        reasons = []

        domain_lower = domain.lower()
        for keyword, points in self.keyword_weights:
            if keyword in domain_lower:
                score += points
                reasons.append(f"Contains suspicious keyword: '{keyword}'")

        return score, reasons

    def _check_substitutions(self, domain_name: str) -> tuple[int, list[str]]:
        """Check for character substitutions (l33t speak, typosquatting)."""
        score = 0
        reasons = []

        # Normalize substitutions
        normalized = domain_name.lower()
        for sub, char in self.substitutions.items():
            normalized = normalized.replace(sub, char)

        # Check if normalized version matches targets
        if normalized != domain_name.lower():
            for pattern in self.target_patterns:
                if pattern in normalized:
                    score += 25
                    reasons.append(f"Character substitution detected: '{domain_name}' → '{normalized}'")
                    break

        return score, reasons

    def quick_filter(self, domain: str) -> bool:
        """Quick check if domain might be interesting (before full scoring)."""
        domain_lower = domain.lower()

        # Best-effort punycode decode to make IDNs filterable at discovery-time.
        candidate = domain_lower
        try:
            if "xn--" in domain_lower:
                decoded = idna.decode(domain_lower)
                if decoded and decoded != domain_lower:
                    candidate = decoded.lower()
        except Exception:
            candidate = domain_lower

        # Check allowlist first
        extracted = tldextract.extract(domain_lower)
        registered = f"{extracted.domain}.{extracted.suffix}"
        if registered in self.allowlist or domain_lower in self.allowlist:
            return False

        # If decoded IDN contains homoglyphs, normalize to improve matching.
        normalized_candidate = candidate
        if not normalized_candidate.isascii():
            normalized_candidate = self._normalize_homoglyphs(normalized_candidate).lower()

        extracted_candidate = tldextract.extract(normalized_candidate)

        # Check if any target pattern is roughly present
        for pattern in self.target_patterns:
            if pattern in domain_lower or pattern in normalized_candidate:
                return True
            # Quick Levenshtein check
            if (
                fuzz.partial_ratio(pattern, extracted.domain) >= 70
                or fuzz.partial_ratio(pattern, extracted_candidate.domain) >= 70
            ):
                return True

        return False
