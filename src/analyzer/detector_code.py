"""Code analysis helpers."""

from __future__ import annotations

from .browser import BrowserResult
from .code_analysis import CodeAnalysisResult


class DetectorCodeMixin:
    """Code analysis helpers."""

    def _analyze_code(self, browser_result: BrowserResult) -> CodeAnalysisResult:
        """Analyze HTML/JavaScript for phishing indicators."""
        html_content = ""
        if browser_result.html:
            html_content += browser_result.html
        if hasattr(browser_result, "html_early") and browser_result.html_early:
            html_content += "\n" + browser_result.html_early

        network_urls = ""
        if browser_result.external_requests:
            network_urls = "\n".join(browser_result.external_requests)

        result = self._code_analyzer.analyze(
            domain=browser_result.domain,
            html=html_content,
        )

        if network_urls:
            extra_endpoints = self._code_analyzer._extract_c2_endpoints(network_urls)
            if extra_endpoints:
                merged = list({*result.c2_endpoints, *extra_endpoints})
                result.c2_endpoints = merged[:20]
                result.calculate_risk_score()

        return result
