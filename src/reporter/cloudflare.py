"""Cloudflare abuse form reporter for SeedBuster."""

import logging
import os
import re
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
    manual_only = True  # Turnstile/CAPTCHA almost always blocks automation

    ABUSE_FORM_URL = "https://abuse.cloudflare.com/phishing"
    SUBMIT_URL = "https://abuse.cloudflare.com/api/v1/phishing"

    def __init__(
        self,
        reporter_email: str = "",
        *,
        reporter_name: str = "",
        reporter_title: str = "",
        reporter_company: str = "",
        reporter_telephone: str = "",
        targeted_brand: str = "",
        reported_country: str = "",
        reported_user_agent: str = "",
    ):
        super().__init__()
        parsed_name, parsed_email = self._parse_name_email(reporter_email)
        self.reporter_email = parsed_email
        self.reporter_name = (
            reporter_name.strip()
            or os.environ.get("CLOUDFLARE_REPORTER_NAME", "").strip()
            or parsed_name
            or "SeedBuster"
        )
        self.reporter_title = reporter_title or os.environ.get("CLOUDFLARE_REPORTER_TITLE", "")
        self.reporter_company = reporter_company or os.environ.get("CLOUDFLARE_REPORTER_COMPANY", "")
        self.reporter_telephone = reporter_telephone or os.environ.get("CLOUDFLARE_REPORTER_TELEPHONE", "")
        self.targeted_brand = targeted_brand or os.environ.get("CLOUDFLARE_TARGETED_BRAND", "")
        self.reported_country = reported_country or os.environ.get("CLOUDFLARE_REPORTED_COUNTRY", "")
        self.reported_user_agent = reported_user_agent or os.environ.get("CLOUDFLARE_REPORTED_USER_AGENT", "")
        self._configured = True  # Always available

    @staticmethod
    def _parse_name_email(value: str) -> tuple[str, str]:
        """Parse `Name <email>` into (name, email)."""
        raw = (value or "").strip()
        if "<" in raw and ">" in raw:
            name = raw.split("<", 1)[0].strip().strip('"')
            email = raw.split("<", 1)[1].split(">", 1)[0].strip()
            return name, email
        return "", raw

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

    def _build_public_justification(self, evidence: ReportEvidence) -> str:
        """Text for Cloudflare's 'Logs or other evidence of abuse' (may be public)."""
        report = ReportTemplates.cloudflare(evidence, "")
        return str(report.get("body") or "").strip()

    def _build_internal_comments(self, evidence: ReportEvidence) -> str:
        """Text for Cloudflare's 'Comments' (kept internal to Cloudflare)."""
        lines: list[str] = []
        if evidence.backend_domains:
            lines.append("Backend infrastructure (hostnames observed):")
            lines.extend(f"- {b}" for b in evidence.backend_domains[:10])
            lines.append("")
        if evidence.suspicious_endpoints:
            lines.append("Observed data collection endpoints:")
            lines.extend(f"- {u}" for u in evidence.suspicious_endpoints[:10])
            lines.append("")
        if evidence.screenshot_path or evidence.html_path:
            lines.append("Captured evidence (screenshot + HTML) available on request.")
        return "\n".join(lines).strip()

    def _build_manual_payload(
        self, evidence: ReportEvidence, *, reason: str
    ) -> tuple[str, ManualSubmissionData]:
        """Build manual submission payload with both plain text and structured data."""
        justification = self._build_public_justification(evidence)
        internal_comments = self._build_internal_comments(evidence)

        email = (self.reporter_email or "").strip()
        name = (self.reporter_name or "").strip()
        title = (self.reporter_title or "").strip()
        company = (self.reporter_company or "").strip()
        tele = (self.reporter_telephone or "").strip()
        targeted_brand = (self.targeted_brand or "").strip()
        reported_country = (self.reported_country or "").strip()
        reported_user_agent = (self.reported_user_agent or "").strip()

        # Build structured data for the new UI
        fields: list[ManualSubmissionField] = [
            ManualSubmissionField(
                name="name",
                label="Your full name",
                value=name or "(fill manually)",
            ),
            ManualSubmissionField(
                name="email",
                label="Your email address",
                value=email or "(fill manually)",
            ),
            ManualSubmissionField(
                name="email2",
                label="Confirm email address",
                value=email or "(fill manually)",
            ),
        ]

        if title:
            fields.append(
                ManualSubmissionField(name="title", label="Title (optional)", value=title)
            )
        if company:
            fields.append(
                ManualSubmissionField(
                    name="company", label="Company name (optional)", value=company
                )
            )
        if tele:
            fields.append(
                ManualSubmissionField(
                    name="tele", label="Telephone (optional)", value=tele
                )
            )

        fields.append(
            ManualSubmissionField(
                name="urls",
                label="Evidence URLs (one per line)",
                value=evidence.url,
                multiline=True,
            )
        )
        fields.append(
            ManualSubmissionField(
                name="justification",
                label="Logs or other evidence of abuse (may be released publicly)",
                value=justification,
                multiline=True,
            )
        )

        if targeted_brand:
            fields.append(
                ManualSubmissionField(
                    name="original_work",
                    label="Targeted Brand (optional)",
                    value=targeted_brand,
                )
            )

        if reported_country:
            fields.append(
                ManualSubmissionField(
                    name="reported_country",
                    label="Reporter current country (optional)",
                    value=reported_country,
                )
            )
        if reported_user_agent:
            fields.append(
                ManualSubmissionField(
                    name="reported_user_agent",
                    label="User agent (optional)",
                    value=reported_user_agent,
                )
            )

        if internal_comments:
            fields.append(
                ManualSubmissionField(
                    name="comments",
                    label="Comments (internal to Cloudflare)",
                    value=internal_comments,
                    multiline=True,
                )
            )

        # Add notification preference guidance (checkboxes on the form)
        fields.append(
            ManualSubmissionField(
                name="notification_prefs",
                label="Who should be notified? (checkboxes)",
                value=(
                    "☑ Please forward my report to the website hosting provider.\n"
                    "☐ Include my name and contact information with the report to the hosting provider.\n"
                    "☑ Please forward my report to the website owner.\n"
                    "☐ Include my name and contact information with the report to the website owner.\n\n"
                    "→ Check the boxes above on the form. Uncheck 'Include my name' if you prefer anonymity."
                ),
                multiline=True,
            )
        )

        # Add DSA certification reminder (required checkbox)
        fields.append(
            ManualSubmissionField(
                name="dsa_certification",
                label="DSA Certification (required checkbox)",
                value=(
                    "☑ I understand and agree\n\n"
                    "→ You MUST check this box to submit the form."
                ),
                multiline=True,
            )
        )

        notes = [
            "Complete the Turnstile challenge before submitting.",
            "The notification checkboxes determine who receives your report - check at least one forwarding option.",
            "The DSA certification checkbox is REQUIRED to submit the form.",
        ]

        manual_data = ManualSubmissionData(
            form_url=self.ABUSE_FORM_URL,
            reason=reason,
            fields=fields,
            notes=notes,
        )

        # Build plain text message for backwards compatibility
        lines = [
            f"Manual submission required ({reason}): {self.ABUSE_FORM_URL}",
            "",
            "Cloudflare form fields:",
            f"- Your full name: {name or '(fill manually)'}",
            f"- Your email address: {email or '(fill manually)'}",
            f"- Confirm email address: {email or '(fill manually)'}",
        ]
        if title:
            lines.append(f"- Title (optional): {title}")
        if company:
            lines.append(f"- Company name (optional): {company}")
        if tele:
            lines.append(f"- Telephone (optional): {tele}")

        lines.extend(
            [
                "- Evidence URLs (one per line):",
                evidence.url,
                "",
                "- Logs or other evidence of abuse (may be released publicly):",
                justification,
            ]
        )

        if targeted_brand:
            lines.extend(["", "- Targeted Brand (optional):", targeted_brand])

        if reported_country:
            lines.extend(["", f"- Reporter current country (optional): {reported_country}"])
        if reported_user_agent:
            lines.append(f"- User agent (optional): {reported_user_agent}")

        if internal_comments:
            lines.extend(["", "- Comments (internal to Cloudflare):", internal_comments])

        lines.extend(
            [
                "",
                "- Who should be notified? (checkboxes on form):",
                "  ☑ Please forward my report to the website hosting provider.",
                "  ☐ Include my name and contact information with the report to the hosting provider.",
                "  ☑ Please forward my report to the website owner.",
                "  ☐ Include my name and contact information with the report to the website owner.",
                "",
                "- DSA Certification (required checkbox):",
                "  ☑ I understand and agree",
                "",
                "Notes:",
                "- " + notes[0],
                "- " + notes[1],
                "- " + notes[2],
            ]
        )

        return "\n".join(lines).strip(), manual_data

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        """Generate structured manual submission data for public instructions."""
        _, manual_data = self._build_manual_payload(evidence, reason="Manual submission required")
        return manual_data

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

        justification = self._build_public_justification(evidence)
        internal_comments = self._build_internal_comments(evidence)

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
                    msg, manual_data = self._build_manual_payload(
                        evidence, reason=f"HTTP {form_resp.status_code}"
                    )
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.MANUAL_REQUIRED,
                        message=msg,
                        response_data={"manual_fields": manual_data.to_dict()},
                    )

                page_lower = (form_resp.text or "").lower()
                if any(token in page_lower for token in ("cf-turnstile", "turnstile", "captcha", "cf-challenge")):
                    msg, manual_data = self._build_manual_payload(
                        evidence, reason="Turnstile/CAPTCHA"
                    )
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.MANUAL_REQUIRED,
                        message=msg,
                        response_data={"manual_fields": manual_data.to_dict()},
                    )

                csrf_token = self._extract_csrf_token_from_html(form_resp.text)

                # Prepare form data
                form_data = {
                    "name": self.reporter_name,
                    "email": self.reporter_email,
                    "email2": self.reporter_email,
                    "title": self.reporter_title,
                    "company": self.reporter_company,
                    "tele": self.reporter_telephone,
                    "urls": evidence.url,
                    "justification": justification,
                    "original_work": self.targeted_brand,
                    "reported_country": self.reported_country,
                    "reported_user_agent": self.reported_user_agent,
                    "comments": internal_comments,
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
                        msg, manual_data = self._build_manual_payload(
                            evidence, reason="Submission not confirmed"
                        )
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.MANUAL_REQUIRED,
                            message=msg,
                            response_data={"manual_fields": manual_data.to_dict()},
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
                msg, manual_data = self._build_manual_payload(
                    evidence, reason=f"Auto-submit failed: {e}"
                )
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.MANUAL_REQUIRED,
                    message=msg,
                    response_data={"manual_fields": manual_data.to_dict()},
                )
