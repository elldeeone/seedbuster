"""Content analysis helpers."""

from __future__ import annotations

import re

from .browser import BrowserResult


class DetectorContentMixin:
    """Content keyword and evasion helpers."""

    def _detect_keywords(self, html: str) -> tuple[int, list[str]]:
        """Detect phishing keywords in HTML content."""
        score = 0
        reasons: list[str] = []
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

        for keyword in self.keywords:
            if keyword.lower() in html_lower:
                score += 5
                found_keywords.append(keyword)

        return score, reasons

    def _check_title(self, title: str) -> tuple[int, list[str]]:
        """Check page title for suspicious patterns."""
        score = 0
        reasons: list[str] = []
        title_lower = title.lower()

        for keyword, points, reason in self.title_keywords:
            if keyword in title_lower:
                score += points
                reasons.append(reason)

        return score, reasons

    def _detect_evasion(self, result: BrowserResult) -> tuple[int, list[str]]:
        """Detect anti-bot evasion techniques."""
        score = 0
        reasons: list[str] = []

        if hasattr(result, "blocked_requests") and result.blocked_requests:
            score += 15
            blocked_count = len(result.blocked_requests)
            services = set()
            for url in result.blocked_requests:
                try:
                    domain = url.split("/")[2]
                    services.add(domain.split(".")[-2])
                except Exception:
                    pass
            if services:
                reasons.append(
                    f"Anti-bot services blocked: {', '.join(services)} ({blocked_count} requests)"
                )
            else:
                reasons.append(f"Anti-bot services blocked ({blocked_count} requests)")

        if hasattr(result, "evasion_detected") and result.evasion_detected:
            score += 20
            if result.title_early and result.title:
                reasons.append(
                    "Evasion detected: title changed from "
                    f"'{result.title_early[:30]}...' to '{result.title[:30]}...'"
                )
            else:
                reasons.append("Evasion detected: page content changed after load")

        if hasattr(result, "html_early") and result.html_early:
            early_keyword_score, early_reasons = self._detect_keywords(result.html_early)
            if early_keyword_score > 0 and hasattr(result, "evasion_detected") and result.evasion_detected:
                score += early_keyword_score
                for reason in early_reasons:
                    reasons.append(f"[Early capture] {reason}")

        return score, reasons
