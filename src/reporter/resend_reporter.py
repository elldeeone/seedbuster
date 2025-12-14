"""Resend email reporter for SeedBuster."""

import logging
from typing import Optional

import httpx

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus
from .rdap import lookup_registrar_via_rdap
from .templates import ReportTemplates

logger = logging.getLogger(__name__)

# Abuse contacts by hosting provider
# Note: Many providers use web forms instead of email now
# These are the ones that still accept email reports
ABUSE_CONTACTS = {
    "namecheap": "abuse@namecheap.com",
    "godaddy": "abuse@godaddy.com",
    "hostinger": "abuse@hostinger.com",
    "ovh": "abuse@ovh.net",
    "hetzner": "abuse@hetzner.com",
}

# Providers that require web form submission
ABUSE_FORMS = {
    "digitalocean": "https://www.digitalocean.com/company/contact/abuse",
    "cloudflare": "https://abuse.cloudflare.com/",
    "aws": "https://support.aws.amazon.com/#/contacts/report-abuse",
    "azure": "https://msrc.microsoft.com/report/abuse",
    "google": "https://support.google.com/code/contact/cloud_platform_report",
    "vultr": "https://www.vultr.com/company/abuse/",
    "linode": "https://www.linode.com/legal-abuse/",
    "vercel": "https://vercel.com/abuse",
    "netlify": "https://www.netlify.com/abuse/",
    "heroku": "https://www.heroku.com/policy/aup-reporting",
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

    def get_abuse_contact(self, evidence: ReportEvidence) -> tuple[Optional[str], Optional[str]]:
        """
        Determine the appropriate abuse contact based on evidence.

        Returns:
            (email, form_url) - email if available, form_url if manual submission needed
        """
        # Check backend domains for hosting provider indicators
        for domain in evidence.backend_domains or []:
            domain_lower = domain.lower()

            if "ondigitalocean.app" in domain_lower or "digitalocean" in domain_lower:
                return (None, ABUSE_FORMS["digitalocean"])
            elif "cloudflare" in domain_lower or "workers.dev" in domain_lower:
                return (None, ABUSE_FORMS["cloudflare"])
            elif "vercel" in domain_lower:
                return (None, ABUSE_FORMS["vercel"])
            elif "netlify" in domain_lower:
                return (None, ABUSE_FORMS["netlify"])
            elif "herokuapp" in domain_lower:
                return (None, ABUSE_FORMS["heroku"])
            elif "amazonaws" in domain_lower or "aws" in domain_lower:
                return (None, ABUSE_FORMS["aws"])
            elif "azure" in domain_lower:
                return (None, ABUSE_FORMS["azure"])

        # Check hosting provider field for email contacts
        if evidence.hosting_provider:
            provider_lower = evidence.hosting_provider.lower()
            for key, email in ABUSE_CONTACTS.items():
                if key in provider_lower:
                    return (email, None)
            # Check for form-based providers
            for key, form_url in ABUSE_FORMS.items():
                if key in provider_lower:
                    return (None, form_url)

        return (None, None)

    @staticmethod
    def _match_known_abuse_email(registrar_name: Optional[str]) -> Optional[str]:
        """Map a registrar name to a known abuse email (best-effort substring match)."""
        key = (registrar_name or "").strip().lower()
        if not key:
            return None
        for needle, email in ABUSE_CONTACTS.items():
            if needle in key:
                return email
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
        to_email, form_url = self.get_abuse_contact(evidence)
        registrar_name: Optional[str] = None
        use_registrar_template = False

        # If provider requires web form, return the URL for manual submission
        if form_url and not to_email:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.MANUAL_REQUIRED,
                message=(
                    f"Manual submission required: {form_url}\n\n"
                    f"Evidence summary:\n{evidence.to_summary()}"
                ),
            )

        if not to_email:
            lookup = await lookup_registrar_via_rdap(evidence.domain)
            registrar_name = lookup.registrar_name
            to_email = lookup.abuse_email or self._match_known_abuse_email(registrar_name)
            if to_email:
                use_registrar_template = True
            else:
                detail = f"{lookup.error}: {lookup.rdap_url}" if lookup.error else f"RDAP: {lookup.rdap_url}"
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.SKIPPED,
                    message=f"Could not determine abuse contact for this domain ({detail})",
                )

        # Generate appropriate template
        if use_registrar_template:
            report = ReportTemplates.registrar(
                evidence,
                reporter_email=self.from_email,
                registrar_name=registrar_name,
            )
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
