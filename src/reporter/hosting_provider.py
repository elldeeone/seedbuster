"""Hosting provider manual reporter for SeedBuster.

This reporter does not attempt automation. It provides the most relevant abuse
destination (web form or email) based on infrastructure hints, along with a
copy/paste-ready evidence summary.
"""

import logging
from typing import Optional

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus
from .templates import ReportTemplates

logger = logging.getLogger(__name__)


# Provider abuse form URLs (best-effort; providers may change these).
ABUSE_FORMS: dict[str, str] = {
    "digitalocean": "https://www.digitalocean.com/company/contact/abuse",
    "cloudflare": "https://abuse.cloudflare.com/phishing",
    "aws": "https://support.aws.amazon.com/#/contacts/report-abuse",
    "azure": "https://msrc.microsoft.com/report/abuse",
    "google": "https://support.google.com/code/contact/cloud_platform_report",
    "vultr": "https://www.vultr.com/company/abuse/",
    "linode": "https://www.linode.com/legal-abuse/",
    "vercel": "https://vercel.com/abuse",
    "netlify": "https://www.netlify.com/abuse/",
    "heroku": "https://www.heroku.com/policy/aup-reporting",
}


# Provider abuse email contacts (best-effort; some providers prefer forms).
ABUSE_EMAILS: dict[str, str] = {
    "namecheap": "abuse@namecheap.com",
    "godaddy": "abuse@godaddy.com",
    "hostinger": "abuse@hostinger.com",
    "ovh": "abuse@ovh.net",
    "hetzner": "abuse@hetzner.com",
}


class HostingProviderReporter(BaseReporter):
    """
    Hosting provider manual reporting helper.

    This reporter is intended to be enabled explicitly via `REPORT_PLATFORMS`.
    """

    platform_name = "hosting_provider"
    platform_url = ""
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 60

    def __init__(self, reporter_email: str = ""):
        super().__init__()
        self.reporter_email = reporter_email
        self._configured = True

    @staticmethod
    def _detect_provider_from_evidence(evidence: ReportEvidence) -> Optional[str]:
        provider = (evidence.hosting_provider or "").strip().lower()
        if provider:
            return provider

        # Fall back to backend-domain patterns.
        haystack = " ".join((evidence.backend_domains or []) + (evidence.suspicious_endpoints or [])).lower()
        if "ondigitalocean.app" in haystack or "digitalocean" in haystack:
            return "digitalocean"
        if "workers.dev" in haystack or "cloudflare" in haystack:
            return "cloudflare"
        if "vercel" in haystack:
            return "vercel"
        if "netlify" in haystack:
            return "netlify"
        if "herokuapp" in haystack:
            return "heroku"

        return None

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """Return manual instructions for the best-matching hosting provider."""
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        provider = self._detect_provider_from_evidence(evidence)
        if not provider:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message="Could not determine hosting provider for manual reporting",
            )

        form_url = ABUSE_FORMS.get(provider)
        email = ABUSE_EMAILS.get(provider)

        if not form_url and not email:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=f"No known abuse destination for provider: {provider}",
            )

        parts: list[str] = [
            f"Hosting provider detected: {provider}",
            "",
        ]

        if form_url:
            parts.extend([
                f"Manual submission (web form): {form_url}",
                "",
                f"URL: {evidence.url}",
                "",
            ])

        if email:
            try:
                template = ReportTemplates.generic_email(evidence, self.reporter_email or "your-email@example.com")
                parts.extend([
                    f"Manual submission (email): {email}",
                    "",
                    f"Subject: {template['subject']}",
                    "",
                    template["body"].strip(),
                    "",
                ])
            except Exception as e:
                logger.warning(f"Failed to build email template: {e}")
                parts.extend([
                    f"Manual submission (email): {email}",
                    "",
                    "Evidence summary:",
                    evidence.to_summary().strip(),
                    "",
                ])

        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message="\n".join(parts).strip(),
        )

