"""Hosting provider manual reporter for SeedBuster.

This reporter does not attempt automation. It provides the most relevant abuse
destination (web form or email) based on infrastructure hints, along with a
copy/paste-ready evidence summary.
"""

import logging
from typing import Optional

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
    "contabo": "https://contabo.com/en/company/contact/",
    "dreamhost": "https://www.dreamhost.com/company/contact/",
}


# Provider abuse email contacts (best-effort; some providers prefer forms).
ABUSE_EMAILS: dict[str, str] = {
    "namecheap": "abuse@namecheap.com",
    "godaddy": "abuse@godaddy.com",
    "hostinger": "abuse@hostinger.com",
    "ovh": "abuse@ovh.net",
    "hetzner": "abuse@hetzner.com",
    "contabo": "abuse@contabo.com",
    "cogent": "abuse@cogentco.com",
    "rackforest": "abuse@rackforest.com",
    "dreamhost": "abuse@dreamhost.com",
    "trellian": "abuse@trellian.com",
    "internetbilisim": "abuse@ultahost.com",
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
    manual_only = True

    def __init__(self, reporter_email: str = ""):
        super().__init__()
        self.reporter_email = reporter_email
        self._configured = True

    @staticmethod
    def _detect_provider_from_evidence(evidence: ReportEvidence) -> Optional[str]:
        provider = (evidence.hosting_provider or "").strip().lower()
        if provider:
            for key in list(ABUSE_FORMS.keys()) + list(ABUSE_EMAILS.keys()):
                if key in provider:
                    return key
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
        if "aws" in haystack or "cloudfront" in haystack or "amazonaws" in haystack:
            return "aws"

        return None

    @staticmethod
    def _extract_ips(evidence: ReportEvidence) -> list[str]:
        ips: list[str] = []
        try:
            infra = evidence.analysis_json.get("infrastructure") if evidence.analysis_json else {}
            if infra:
                ips = infra.get("ip_addresses") or infra.get("resolved_ips") or []
                if isinstance(ips, str):
                    ips = [ips]
        except Exception:
            ips = []
        return ips

    def _build_manual_submission(
        self,
        evidence: ReportEvidence,
        *,
        provider: str,
        form_url: Optional[str],
        email: Optional[str],
        ips: list[str],
    ) -> ManualSubmissionData:
        fields: list[ManualSubmissionField] = [
            ManualSubmissionField(
                name="url",
                label="Phishing URL",
                value=evidence.url,
            ),
        ]
        if ips:
            fields.append(
                ManualSubmissionField(
                    name="ip_addresses",
                    label="IP address(es)",
                    value=", ".join(ips),
                )
            )

        evidence_summary = evidence.to_summary().strip()
        if ips:
            evidence_summary = f"IPs: {', '.join(ips)}\n\n" + evidence_summary

        if email:
            try:
                template = ReportTemplates.generic_email(
                    evidence, self.reporter_email or "your-email@example.com"
                )
                fields.extend([
                    ManualSubmissionField(
                        name="to",
                        label="Send email to",
                        value=email,
                    ),
                    ManualSubmissionField(
                        name="subject",
                        label="Subject line",
                        value=template["subject"],
                    ),
                    ManualSubmissionField(
                        name="body",
                        label="Email body",
                        value=template["body"].strip(),
                        multiline=True,
                    ),
                ])
            except Exception as e:
                logger.warning(f"Failed to build email template: {e}")
                fields.append(
                    ManualSubmissionField(
                        name="evidence",
                        label="Evidence summary",
                        value=evidence_summary,
                        multiline=True,
                    )
                )
        else:
            fields.append(
                ManualSubmissionField(
                    name="evidence",
                    label="Evidence summary",
                    value=evidence_summary,
                    multiline=True,
                )
            )

        destination_url = form_url or f"mailto:{email}" if email else ""

        notes = [
            f"Detected hosting provider: {provider.upper()}",
            "Submit via the abuse form or email the abuse contact.",
        ]
        if not form_url and not email:
            notes.append("No specific abuse contact found; use the provider/ASN WHOIS abuse email.")

        return ManualSubmissionData(
            form_url=destination_url,
            reason=f"Hosting provider: {provider}",
            fields=fields,
            notes=notes,
        )

    def is_applicable(self, evidence: ReportEvidence) -> tuple[bool, str]:
        provider = self._detect_provider_from_evidence(evidence)
        if not provider:
            return False, "No hosting provider identified"
        return True, ""

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        provider = self._detect_provider_from_evidence(evidence)
        if not provider:
            return ManualSubmissionData(
                form_url="",
                reason="Hosting provider not identified",
                fields=[
                    ManualSubmissionField(
                        name="url",
                        label="Phishing URL",
                        value=evidence.url,
                    )
                ],
                notes=["No hosting provider identified from this evidence."],
            )

        form_url = ABUSE_FORMS.get(provider)
        email = ABUSE_EMAILS.get(provider)
        ips = self._extract_ips(evidence)
        return self._build_manual_submission(
            evidence,
            provider=provider,
            form_url=form_url,
            email=email,
            ips=ips,
        )

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
                status=ReportStatus.SKIPPED,
                message="No hosting provider identified",
            )

        form_url = ABUSE_FORMS.get(provider)
        email = ABUSE_EMAILS.get(provider)
        ips = self._extract_ips(evidence)
        manual_data = self._build_manual_submission(
            evidence,
            provider=provider,
            form_url=form_url,
            email=email,
            ips=ips,
        )

        if not form_url and not email:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.MANUAL_REQUIRED,
                message=f"No known abuse destination for provider: {provider}",
                response_data={"manual_fields": manual_data.to_dict()},
            )

        # Build plain text message for backwards compatibility
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
                template = ReportTemplates.generic_email(
                    evidence, self.reporter_email or "your-email@example.com"
                )
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
                    evidence_summary,
                    "",
                ])

        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message="\n".join(parts).strip(),
            response_data={"manual_fields": manual_data.to_dict()},
        )
