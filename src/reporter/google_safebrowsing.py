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
from .templates import ReportTemplates

logger = logging.getLogger(__name__)


class GoogleSafeBrowsingReporter(BaseReporter):
    """
    Google Safe Browsing report form.

    Note: Google uses reCAPTCHA which prevents full automation.
    This reporter generates a pre-filled URL for manual submission.
    """

    platform_name = "google_safebrowsing"
    platform_url = "https://safebrowsing.google.com/safebrowsing/report_phish/"
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 10
    manual_only = True

    PHISH_FORM_URL = "https://safebrowsing.google.com/safebrowsing/report_phish/"
    UNSAFE_FORM_URL = "https://safebrowsing.google.com/safebrowsing/report-url"

    def __init__(self):
        super().__init__()
        self._configured = True  # Always available, no config needed

    def _use_phishing_form(self, evidence: ReportEvidence) -> bool:
        return evidence.resolve_scam_type() == "seed_phishing"

    def get_form_url(self, evidence: ReportEvidence) -> str:
        return self.PHISH_FORM_URL if self._use_phishing_form(evidence) else self.UNSAFE_FORM_URL

    def _url_field_label(self, evidence: ReportEvidence) -> str:
        if self._use_phishing_form(evidence):
            return "URL of the phishing page"
        return "URL of the unsafe site"

    def get_prefilled_url(self, evidence: ReportEvidence) -> str:
        """Generate URL with pre-filled parameters (if supported)."""
        # Google's form doesn't support URL params, so just return base URL
        return self.get_form_url(evidence)

    def get_report_text(self, evidence: ReportEvidence) -> str:
        """Generate the additional details text for copy-paste."""
        details = ReportTemplates.google_safebrowsing_comment(evidence)
        return details[:790]

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """
        Submit report to Google Safe Browsing.

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

        form_url = self.get_form_url(evidence)
        url_label = self._url_field_label(evidence)

        # Build structured data for the new UI
        manual_data = ManualSubmissionData(
            form_url=form_url,
            reason="reCAPTCHA",
            fields=[
                ManualSubmissionField(
                    name="url",
                    label=url_label,
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
                f"Manual submission required (reCAPTCHA): {form_url}\n\n"
                f"URL: {evidence.url}\n\n"
                f"Copy/paste details:\n{report_text}"
            ),
            response_data={"manual_fields": manual_data.to_dict()},
        )
