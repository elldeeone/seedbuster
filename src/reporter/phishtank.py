"""PhishTank reporter for SeedBuster."""

import logging
from typing import Optional

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


class PhishTankReporter(BaseReporter):
    """
    PhishTank phishing database reporter.

    PhishTank is a community-driven phishing verification service.
    API key is optional but recommended for higher rate limits.

    Submission is via web form (API is read-only for checking URLs).
    """

    platform_name = "phishtank"
    platform_url = "https://phishtank.org"
    supports_evidence = False
    requires_api_key = False
    rate_limit_per_minute = 30

    # PhishTank endpoints
    CHECK_URL = "https://checkurl.phishtank.com/checkurl/"
    SUBMIT_URL = "https://www.phishtank.com/phish_submit.php"

    def __init__(self, api_key: Optional[str] = None):
        super().__init__()
        self.api_key = api_key
        self._configured = True  # Always available

    async def check_duplicate(self, url: str) -> bool:
        """Check if URL is already in PhishTank database."""
        if not self.api_key:
            return False  # Can't check without API key

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                data = {
                    "url": url,
                    "format": "json",
                    "app_key": self.api_key,
                }

                resp = await client.post(
                    self.CHECK_URL,
                    data=data,
                    headers={"User-Agent": "SeedBuster/1.0"},
                )

                if resp.status_code == 200:
                    result = resp.json()
                    # If in_database is true, it's already reported
                    return result.get("results", {}).get("in_database", False)

            except Exception as e:
                logger.warning(f"PhishTank duplicate check failed: {e}")

        return False

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """
        Submit URL to PhishTank.

        Note: PhishTank's submission is via web form, not API.
        We simulate the form submission.
        """
        # Validate evidence
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        # Check for duplicates first
        if await self.check_duplicate(evidence.url):
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.DUPLICATE,
                message="URL already in PhishTank database",
            )

        # Generate comment
        comment = ReportTemplates.phishtank_comment(evidence)

        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            try:
                # PhishTank submission form
                # Note: This may require a logged-in session for full functionality
                data = {
                    "phish_url": evidence.url,
                    "phish_detail": comment,
                    "phish_target": "cryptocurrency",
                }

                resp = await client.post(
                    self.SUBMIT_URL,
                    data=data,
                    headers={
                        "User-Agent": "SeedBuster/1.0",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )

                # PhishTank returns 200 even for errors, check response content
                if resp.status_code == 200:
                    # Check for success indicators in response
                    response_text = resp.text.lower()

                    if "thank you" in response_text or "submitted" in response_text:
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.SUBMITTED,
                            message="Submitted to PhishTank",
                        )
                    elif "already" in response_text or "duplicate" in response_text:
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.DUPLICATE,
                            message="URL already reported",
                        )
                    elif "login" in response_text or "sign in" in response_text:
                        # Submission requires login
                        manual_data = ManualSubmissionData(
                            form_url=self.SUBMIT_URL,
                            reason="Login required",
                            fields=[
                                ManualSubmissionField(
                                    name="url",
                                    label="Phishing URL",
                                    value=evidence.url,
                                ),
                                ManualSubmissionField(
                                    name="details",
                                    label="Details / Comments",
                                    value=comment,
                                    multiline=True,
                                ),
                            ],
                            notes=[
                                "PhishTank requires a login to submit reports.",
                                "Create a free account at phishtank.org if needed.",
                            ],
                        )
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.MANUAL_REQUIRED,
                            message=(
                                f"PhishTank requires login; manual submission required: {self.SUBMIT_URL}\n\n"
                                f"URL: {evidence.url}\n\n"
                                f"Copy/paste details:\n{comment}"
                            ),
                            response_data={"manual_fields": manual_data.to_dict()},
                        )
                    else:
                        # Don't assume success if we can't confirm.
                        logger.warning("PhishTank submission not confirmed; returning manual instructions")
                        manual_data = ManualSubmissionData(
                            form_url=self.SUBMIT_URL,
                            reason="Submission not confirmed",
                            fields=[
                                ManualSubmissionField(
                                    name="url",
                                    label="Phishing URL",
                                    value=evidence.url,
                                ),
                                ManualSubmissionField(
                                    name="details",
                                    label="Details / Comments",
                                    value=comment,
                                    multiline=True,
                                ),
                            ],
                            notes=[
                                "PhishTank may require a login to submit reports.",
                            ],
                        )
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.MANUAL_REQUIRED,
                            message=(
                                f"Submission not confirmed; manual submission recommended: {self.SUBMIT_URL}\n\n"
                                f"URL: {evidence.url}\n\n"
                                f"Copy/paste details:\n{comment}"
                            ),
                            response_data={"manual_fields": manual_data.to_dict()},
                        )

                else:
                    raise APIError(
                        resp.status_code,
                        f"PhishTank returned {resp.status_code}",
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
                logger.exception("PhishTank submission error")
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.FAILED,
                    message=f"Submission failed: {e}",
                )
