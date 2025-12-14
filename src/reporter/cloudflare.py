"""Cloudflare abuse form reporter for SeedBuster."""

import logging
import re
from typing import Optional

import httpx

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus, APIError
from .templates import ReportTemplates

logger = logging.getLogger(__name__)


class CloudflareReporter(BaseReporter):
    """
    Cloudflare abuse form reporter.

    Submits phishing reports via Cloudflare's abuse form.
    This is free and doesn't require authentication.
    """

    platform_name = "cloudflare"
    platform_url = "https://abuse.cloudflare.com"
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 10

    ABUSE_FORM_URL = "https://abuse.cloudflare.com/phishing"
    SUBMIT_URL = "https://abuse.cloudflare.com/api/v1/phishing"

    def __init__(self, reporter_email: str = ""):
        super().__init__()
        self.reporter_email = reporter_email
        self._configured = True  # Always available

    @staticmethod
    def _extract_csrf_token_from_html(html: str) -> Optional[str]:
        """Extract CSRF token from Cloudflare abuse form HTML."""
        patterns = [
            r'name="csrf_token"\s+value="([^"]+)"',
            r'name="_csrf"\s+value="([^"]+)"',
            r'"csrfToken":\s*"([^"]+)"',
            r'data-csrf="([^"]+)"',
        ]
        for pattern in patterns:
            match = re.search(pattern, html or "")
            if match:
                return match.group(1)
        return None

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """
        Submit phishing report to Cloudflare.

        Cloudflare's abuse form accepts:
        - URL of the phishing site
        - Abuse type (phishing)
        - Description
        - Reporter email (optional)
        """
        # Validate evidence
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        # Generate report content
        report = ReportTemplates.cloudflare(evidence, self.reporter_email)

        async with httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            },
        ) as client:
            try:
                # Load the form page and detect challenges/CAPTCHA.
                form_resp = await client.get(self.ABUSE_FORM_URL)
                if form_resp.status_code != 200:
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.MANUAL_REQUIRED,
                        message=(
                            f"Manual submission required: {self.ABUSE_FORM_URL}\n\n"
                            f"URL: {evidence.url}\n\n"
                            f"Comments:\n{report['body']}"
                        ),
                    )

                page_lower = (form_resp.text or "").lower()
                if any(token in page_lower for token in ("cf-turnstile", "turnstile", "captcha", "cf-challenge")):
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.MANUAL_REQUIRED,
                        message=(
                            f"Manual submission required (CAPTCHA): {self.ABUSE_FORM_URL}\n\n"
                            f"URL: {evidence.url}\n\n"
                            f"Comments:\n{report['body']}"
                        ),
                    )

                csrf_token = self._extract_csrf_token_from_html(form_resp.text)

                # Prepare form data
                form_data = {
                    "urls": evidence.url,
                    "abuse_type": "phishing",
                    "abuse_type_other": "",
                    "comments": report["body"],
                    "email": self.reporter_email,
                    "name": "SeedBuster",
                }

                if csrf_token:
                    form_data["csrf_token"] = csrf_token

                # Submit the form
                resp = await client.post(
                    self.ABUSE_FORM_URL,
                    data=form_data,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Referer": self.ABUSE_FORM_URL,
                    },
                )

                # Check response
                if resp.status_code in (200, 201, 302):
                    response_text = resp.text.lower()

                    if "thank" in response_text or "received" in response_text:
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.SUBMITTED,
                            message="Submitted to Cloudflare abuse",
                        )
                    elif "already" in response_text:
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.DUPLICATE,
                            message="URL already reported to Cloudflare",
                        )
                    elif "error" in response_text or "invalid" in response_text:
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.FAILED,
                            message="Cloudflare returned an error",
                        )
                    else:
                        # Don't assume success if we can't confirm.
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.MANUAL_REQUIRED,
                            message=(
                                f"Submission not confirmed; manual submission recommended: {self.ABUSE_FORM_URL}\n\n"
                                f"URL: {evidence.url}\n\n"
                                f"Comments:\n{report['body']}"
                            ),
                        )

                elif resp.status_code == 429:
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.RATE_LIMITED,
                        message="Cloudflare rate limit exceeded",
                        retry_after=60,
                    )

                else:
                    raise APIError(
                        resp.status_code,
                        f"Cloudflare returned {resp.status_code}",
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
                logger.exception("Cloudflare submission error")
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.MANUAL_REQUIRED,
                    message=(
                        f"Auto-submit failed: {e}\n\n"
                        f"Manual submission required: {self.ABUSE_FORM_URL}\n\n"
                        f"URL: {evidence.url}\n\n"
                        f"Comments:\n{report['body']}"
                    ),
                )
