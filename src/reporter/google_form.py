"""Google Safe Browsing web form reporter for SeedBuster."""

import logging
import re

import httpx

from .base import (
    BaseReporter,
    ManualSubmissionData,
    ManualSubmissionField,
    ReportEvidence,
    ReportResult,
    ReportStatus,
    APIError,
)
from .templates import ReportTemplates

logger = logging.getLogger(__name__)


class GoogleFormReporter(BaseReporter):
    """
    Google Safe Browsing web form reporter.

    Submits reports via Google's free web form.
    This is free (unlike the Web Risk API) and doesn't require authentication.

    The Web Risk API charges $50+/month for submissions, so we use the
    free web form instead.
    """

    platform_name = "google"
    platform_url = "https://www.google.com/safebrowsing/report_phish/"
    supports_evidence = False
    requires_api_key = False
    rate_limit_per_minute = 10
    manual_only = True  # reCAPTCHA almost always blocks automation

    PHISH_REPORT_URL = "https://www.google.com/safebrowsing/report_phish/"
    UNSAFE_REPORT_URL = "https://www.google.com/safebrowsing/report_phish/"

    def __init__(self):
        super().__init__()
        self._configured = True  # Always available

    def _use_phishing_form(self, evidence: ReportEvidence) -> bool:
        return evidence.resolve_scam_type() == "seed_phishing"

    def get_form_url(self, evidence: ReportEvidence) -> str:
        return self.PHISH_REPORT_URL if self._use_phishing_form(evidence) else self.UNSAFE_REPORT_URL

    def _url_field_label(self, evidence: ReportEvidence) -> str:
        if self._use_phishing_form(evidence):
            return "URL of the suspected phishing page"
        return "URL of the unsafe site"

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        """Generate structured manual submission data for public instructions."""
        additional_info = ReportTemplates.google_safebrowsing_comment(evidence)
        form_url = self.get_form_url(evidence)
        url_label = self._url_field_label(evidence)
        return ManualSubmissionData(
            form_url=form_url,
            reason="Google Safe Browsing form",
            fields=[
                ManualSubmissionField(
                    name="url",
                    label=url_label,
                    value=evidence.url,
                ),
                ManualSubmissionField(
                    name="details",
                    label="Additional details (optional)",
                    value=additional_info,
                    multiline=True,
                ),
            ],
            notes=[
                "Paste the URL into Google's form.",
                "Complete the reCAPTCHA if prompted.",
            ],
        )

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """
        Submit report to Google Safe Browsing.

        Uses the phishing form for seed-phrase theft, otherwise the report-url form.
        """
        # Validate evidence
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        # Generate additional info
        additional_info = ReportTemplates.google_safebrowsing_comment(evidence)
        form_url = self.get_form_url(evidence)
        url_label = self._url_field_label(evidence)

        async with httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            },
        ) as client:
            try:
                # First, load the form page to get any required tokens
                form_resp = await client.get(form_url)

                if form_resp.status_code != 200:
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.FAILED,
                        message=f"Could not load report form: {form_resp.status_code}",
                    )

                # If the form requires CAPTCHA (common), fall back to manual submission.
                page_lower = (form_resp.text or "").lower()
                if any(token in page_lower for token in ("recaptcha", "g-recaptcha", "captcha", "turnstile")):
                    manual_data = ManualSubmissionData(
                        form_url=form_url,
                        reason="reCAPTCHA detected",
                        fields=[
                            ManualSubmissionField(
                                name="url",
                                label=url_label,
                                value=evidence.url,
                            ),
                            ManualSubmissionField(
                                name="details",
                                label="Additional details (optional)",
                                value=additional_info,
                                multiline=True,
                            ),
                        ],
                        notes=[
                            "Paste the URL into Google's form.",
                            "Complete the reCAPTCHA before submitting.",
                        ],
                    )
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.MANUAL_REQUIRED,
                        message=(
                            "Manual submission required (CAPTCHA): "
                            f"{form_url}\n\nURL: {evidence.url}\n\nCopy/paste details:\n{additional_info}"
                        ),
                        response_data={"manual_fields": manual_data.to_dict()},
                    )

                # Look for form action URL and any hidden fields
                form_action = form_url
                hidden_fields = {}

                # Extract hidden input fields
                hidden_pattern = r'<input[^>]+type=["\']hidden["\'][^>]*>'
                for match in re.finditer(hidden_pattern, form_resp.text, re.I):
                    input_html = match.group(0)
                    name_match = re.search(r'name=["\']([^"\']+)["\']', input_html)
                    value_match = re.search(r'value=["\']([^"\']*)["\']', input_html)
                    if name_match:
                        hidden_fields[name_match.group(1)] = (
                            value_match.group(1) if value_match else ""
                        )

                # Prepare form data
                form_data = {
                    **hidden_fields,
                    "url": evidence.url,
                    "dq": additional_info,  # Additional details field
                }

                # Submit the form
                resp = await client.post(
                    form_action,
                    data=form_data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Referer": form_url,
                        "Origin": "https://safebrowsing.google.com",
                    },
                )

                # Check response
                if resp.status_code in (200, 201, 302):
                    response_text = resp.text.lower()

                    if (
                        "thank" in response_text
                        or "received" in response_text
                        or "submitted" in response_text
                    ):
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.SUBMITTED,
                            message="Submitted to Google Safe Browsing",
                        )
                    elif "already" in response_text:
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.DUPLICATE,
                            message="URL already reported to Google",
                        )
                    elif "error" in response_text or "invalid" in response_text:
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.FAILED,
                            message="Google returned an error",
                        )
                    else:
                        # Don't assume success if we can't confirm.
                        manual_data = ManualSubmissionData(
                            form_url=form_url,
                            reason="Submission not confirmed",
                            fields=[
                                ManualSubmissionField(
                                    name="url",
                                    label=url_label,
                                    value=evidence.url,
                                ),
                                ManualSubmissionField(
                                    name="details",
                                    label="Additional details (optional)",
                                    value=additional_info,
                                    multiline=True,
                                ),
                            ],
                            notes=[
                                "Paste the URL into Google's form.",
                                "Complete the reCAPTCHA before submitting.",
                            ],
                        )
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.MANUAL_REQUIRED,
                            message=(
                                "Submission not confirmed; manual submission recommended: "
                                f"{form_url}\n\nURL: {evidence.url}\n\nCopy/paste details:\n{additional_info}"
                            ),
                            response_data={"manual_fields": manual_data.to_dict()},
                        )

                elif resp.status_code == 429:
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.RATE_LIMITED,
                        message="Google rate limit exceeded",
                        retry_after=60,
                    )

                else:
                    raise APIError(
                        resp.status_code,
                        f"Google returned {resp.status_code}",
                        resp.text[:200],
                    )

            except httpx.TimeoutException:
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.FAILED,
                    message="Request timed out",
                )

            except APIError:
                raise

            except Exception as e:
                logger.exception("Google Safe Browsing submission error")
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.FAILED,
                    message=f"Submission failed: {e}",
                )
