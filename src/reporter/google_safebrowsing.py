"""Google Safe Browsing form reporter for SeedBuster."""

import logging

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus

logger = logging.getLogger(__name__)


class GoogleSafeBrowsingReporter(BaseReporter):
    """
    Google Safe Browsing phishing report form.

    Note: Google uses reCAPTCHA which prevents full automation.
    This reporter generates a pre-filled URL for manual submission.
    """

    platform_name = "google_safebrowsing"
    platform_url = "https://safebrowsing.google.com/safebrowsing/report_phish/"
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 10

    FORM_URL = "https://safebrowsing.google.com/safebrowsing/report_phish/"

    def __init__(self):
        super().__init__()
        self._configured = True  # Always available, no config needed

    def get_prefilled_url(self, evidence: ReportEvidence) -> str:
        """Generate URL with pre-filled parameters (if supported)."""
        # Google's form doesn't support URL params, so just return base URL
        return self.FORM_URL

    def get_report_text(self, evidence: ReportEvidence) -> str:
        """Generate the additional details text for copy-paste."""
        details_parts = [
            "Cryptocurrency seed phrase phishing site.",
            f"Confidence: {evidence.confidence_score}%",
            "",
            "Detection reasons:",
        ]
        for reason in evidence.detection_reasons[:3]:
            details_parts.append(f"- {reason}")

        if evidence.backend_domains:
            details_parts.append("")
            details_parts.append("Data exfiltration to:")
            for backend in evidence.backend_domains[:2]:
                details_parts.append(f"- {backend}")

        details_parts.append("")
        details_parts.append("Detected by SeedBuster")

        return "\n".join(details_parts)[:790]

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """
        Submit phishing report to Google Safe Browsing.

        Note: Google uses reCAPTCHA which prevents full automation.
        Returns MANUAL_REQUIRED status with URL for manual submission.
        """
        # Validate evidence
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        # Google uses reCAPTCHA - can't automate fully
        # Return pending with info for manual submission
        report_text = self.get_report_text(evidence)
        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message=(
                f"Manual submission required (reCAPTCHA): {self.FORM_URL}\n\n"
                f"URL: {evidence.url}\n\n"
                f"Copy/paste details:\n{report_text}"
            ),
        )
