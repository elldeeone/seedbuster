"""Resend email reporter for SeedBuster."""

import logging
from typing import Optional

import httpx

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus
from .templates import ReportTemplates

logger = logging.getLogger(__name__)

# Abuse contacts by hosting provider
ABUSE_CONTACTS = {
    "digitalocean": "abuse@digitalocean.com",
    "cloudflare": "abuse@cloudflare.com",
    "namecheap": "abuse@namecheap.com",
    "godaddy": "abuse@godaddy.com",
    "hostinger": "abuse@hostinger.com",
    "bluehost": "abuse@bluehost.com",
    "aws": "abuse@amazonaws.com",
    "azure": "abuse@microsoft.com",
    "google": "abuse@google.com",
    "ovh": "abuse@ovh.net",
    "hetzner": "abuse@hetzner.com",
    "vultr": "abuse@vultr.com",
    "linode": "abuse@linode.com",
    "vercel": "abuse@vercel.com",
    "netlify": "abuse@netlify.com",
    "heroku": "abuse@heroku.com",
}


class ResendReporter(BaseReporter):
    """
    Resend-based email reporter for abuse notifications.

    Uses Resend's simple API to send abuse reports to hosting providers,
    registrars, and other relevant parties.
    """

    platform_name = "resend"
    platform_url = "https://resend.com"
    supports_evidence = True
    requires_api_key = True
    rate_limit_per_minute = 10  # Resend free tier: 100/day

    API_URL = "https://api.resend.com/emails"

    def __init__(
        self,
        api_key: str = "",
        from_email: str = "SeedBuster <onboarding@resend.dev>",
    ):
        super().__init__()
        self.api_key = api_key
        self.from_email = from_email
        self._configured = bool(api_key)

    def get_abuse_contact(self, evidence: ReportEvidence) -> Optional[str]:
        """Determine the appropriate abuse contact based on evidence."""
        # Check backend domains for hosting provider indicators
        for domain in evidence.backend_domains or []:
            domain_lower = domain.lower()

            if "ondigitalocean.app" in domain_lower or "digitalocean" in domain_lower:
                return ABUSE_CONTACTS["digitalocean"]
            elif "cloudflare" in domain_lower or "workers.dev" in domain_lower:
                return ABUSE_CONTACTS["cloudflare"]
            elif "vercel" in domain_lower:
                return ABUSE_CONTACTS["vercel"]
            elif "netlify" in domain_lower:
                return ABUSE_CONTACTS["netlify"]
            elif "herokuapp" in domain_lower:
                return ABUSE_CONTACTS["heroku"]
            elif "amazonaws" in domain_lower or "aws" in domain_lower:
                return ABUSE_CONTACTS["aws"]
            elif "azure" in domain_lower:
                return ABUSE_CONTACTS["azure"]

        # Check hosting provider field
        if evidence.hosting_provider:
            provider_lower = evidence.hosting_provider.lower()
            for key, email in ABUSE_CONTACTS.items():
                if key in provider_lower:
                    return email

        # Default to DigitalOcean if we found DO app platform URLs
        return None

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """Send abuse report via Resend."""
        if not self._configured:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message="Resend API key not configured",
            )

        # Validate evidence
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        # Determine recipient
        to_email = self.get_abuse_contact(evidence)
        if not to_email:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message="Could not determine abuse contact for this domain",
            )

        # Generate appropriate template
        if "digitalocean" in to_email:
            report = ReportTemplates.digitalocean(evidence, self.from_email)
        else:
            report = ReportTemplates.generic_email(evidence, self.from_email)

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.post(
                    self.API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "from": self.from_email,
                        "to": [to_email],
                        "subject": report["subject"],
                        "text": report["body"],
                    },
                )

                if resp.status_code in (200, 201):
                    result = resp.json()
                    email_id = result.get("id", "")
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.SUBMITTED,
                        report_id=email_id,
                        message=f"Sent to {to_email}",
                    )

                elif resp.status_code == 429:
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.RATE_LIMITED,
                        message="Resend rate limit exceeded",
                        retry_after=60,
                    )

                elif resp.status_code == 401:
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.FAILED,
                        message="Invalid Resend API key",
                    )

                else:
                    error_msg = resp.text[:200] if resp.text else f"HTTP {resp.status_code}"
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.FAILED,
                        message=f"Resend error: {error_msg}",
                    )

            except httpx.TimeoutException:
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.FAILED,
                    message="Request timed out",
                )

            except Exception as e:
                logger.exception("Resend submission error")
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.FAILED,
                    message=f"Failed to send: {e}",
                )
