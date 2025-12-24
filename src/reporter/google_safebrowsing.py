"""Google Safe Browsing form reporter for SeedBuster."""

import logging

from .base import (
    BaseReporter,
    ManualSubmissionData,
    ManualSubmissionField,
    ReportEvidence,
    ReportResult,
    ReportStatus,
)

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
    manual_only = True

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
        # Filter and humanize detection reasons
        skip_terms = ("suspicion score", "domain suspicion", "tld", "keyword")
        cleaned_reasons = []
        for reason in evidence.detection_reasons[:4]:
            if any(s in (reason or "").lower() for s in skip_terms):
                continue
            # Humanize the reason
            humanized = (reason or "").strip()
            humanized = humanized.replace("Seed phrase form found via exploration:", "Requests seed phrase:")
            humanized = humanized.replace("Seed phrase form found:", "Requests seed phrase:")
            humanized = humanized.replace(" via exploration", "")
            cleaned_reasons.append(humanized)

        details_parts = [
            "Cryptocurrency seed phrase phishing - steals wallet recovery phrases.",
            "Victims lose all funds immediately and irreversibly.",
            "",
            f"Confidence: {evidence.confidence_score}%",
            "",
            "Key evidence:",
        ]
        for reason in cleaned_reasons[:3]:
            details_parts.append(f"- {reason}")

        if evidence.backend_domains:
            details_parts.append("")
            details_parts.append("Stolen data sent to:")
            for backend in evidence.backend_domains[:2]:
                details_parts.append(f"- {backend}")

        details_parts.append("")
        details_parts.append("Detected by SeedBuster (github.com/elldeeone/seedbuster)")

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
        report_text = self.get_report_text(evidence)

        # Build structured data for the new UI
        manual_data = ManualSubmissionData(
            form_url=self.FORM_URL,
            reason="reCAPTCHA",
            fields=[
                ManualSubmissionField(
                    name="url",
                    label="URL of the phishing page",
                    value=evidence.url,
                ),
                ManualSubmissionField(
                    name="details",
                    label="Additional details (optional)",
                    value=report_text,
                    multiline=True,
                ),
            ],
            notes=[
                "Paste the URL in the form's URL field.",
                "Complete the reCAPTCHA challenge before submitting.",
                "Additional details are optional but help Google's review.",
            ],
        )

        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message=(
                f"Manual submission required (reCAPTCHA): {self.FORM_URL}\n\n"
                f"URL: {evidence.url}\n\n"
                f"Copy/paste details:\n{report_text}"
            ),
            response_data={"manual_fields": manual_data.to_dict()},
        )
