"""Google Safe Browsing web form reporter for SeedBuster."""

import logging
import re

import httpx

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus, APIError
from .templates import ReportTemplates

logger = logging.getLogger(__name__)


class GoogleFormReporter(BaseReporter):
    """
    Google Safe Browsing web form reporter.

    Submits phishing reports via Google's free web form.
    This is free (unlike the Web Risk API) and doesn't require authentication.

    The Web Risk API charges $50+/month for submissions, so we use the
    free web form instead.
    """

    platform_name = "google"
    platform_url = "https://safebrowsing.google.com/safebrowsing/report_phish/"
    supports_evidence = False
    requires_api_key = False
    rate_limit_per_minute = 10

    REPORT_URL = "https://safebrowsing.google.com/safebrowsing/report_phish/"

    def __init__(self):
        super().__init__()
        self._configured = True  # Always available

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """
        Submit phishing report to Google Safe Browsing.

        Uses the free web form at safebrowsing.google.com/safebrowsing/report_phish/
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
                form_resp = await client.get(self.REPORT_URL)

                if form_resp.status_code != 200:
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.FAILED,
                        message=f"Could not load report form: {form_resp.status_code}",
                    )

                # If the form requires CAPTCHA (common), fall back to manual submission.
                page_lower = (form_resp.text or "").lower()
                if any(token in page_lower for token in ("recaptcha", "g-recaptcha", "captcha", "turnstile")):
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.MANUAL_REQUIRED,
                        message=(
                            "Manual submission required (CAPTCHA): "
                            f"{self.REPORT_URL}\n\nCopy/paste details:\n{additional_info}"
                        ),
                    )

                # Look for form action URL and any hidden fields
                form_action = self.REPORT_URL
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
                        "Referer": self.REPORT_URL,
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
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.MANUAL_REQUIRED,
                            message=(
                                "Submission not confirmed; manual submission recommended: "
                                f"{self.REPORT_URL}\n\nCopy/paste details:\n{additional_info}"
                            ),
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
