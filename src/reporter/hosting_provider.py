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
    "abovedomains": "https://www.above.com/contact.html",
    "above.com": "https://www.above.com/contact.html",
    "digitalocean": "https://www.digitalocean.com/company/contact/abuse",
    "cloudflare": "https://abuse.cloudflare.com/",
    "aws": "https://repost.aws/knowledge-center/report-aws-abuse",
    "azure": "https://msrc.microsoft.com/report/abuse",
    "google": "https://support.google.com/code/contact/cloud_platform_report",
    "godaddy": "https://supportcenter.godaddy.com/abusereport",
    "hetzner": "https://abuse.hetzner.com/",
    "hostinger": "https://www.hostinger.com/report-abuse",
    "linode": "https://www.linode.com/legal-abuse/",
    "vercel": "https://vercel.com/abuse",
    "netlify": "https://www.netlify.com/support/?topic=Report+Fraud+or+Abuse",
    "ovh": "https://www.ovh.com/abuse/",
    "contabo": "https://contabo.com/en/abuse/",
    "njalla": "https://njal.la/contact/",
    "ultahost": "https://ultahost.com/report-abuse",
}


# Provider abuse email contacts (best-effort; some providers prefer forms).
ABUSE_EMAILS: dict[str, str] = {
    "ifastnet": "abuse@ifastnet.com",
    "namecheap": "abuse@namecheap.com",
    "dreamhost": "abuse@dreamhost.com",
    "ultahost": "abuse@ultahost.com",
    "vultr": "abuse@vultr.com",
    "streetplug": "support@streetplug.me",
}


DNS_PROVIDER_PATTERNS: dict[str, list[str]] = {
    "cloudflare": ["cloudflare.com"],
    "njalla": ["njalla"],
    "streetplug": ["streetplug.me"],
    "ukyeni": ["ukyeni.com"],
    "ultahost": ["ultahost.com"],
    "abovedomains": ["abovedomains.com"],
    "dreamhost": ["dreamhost.com"],
    "namecheap": ["registrar-servers.com"],
    "godaddy": ["domaincontrol.com"],
    "porkbun": ["porkbun.com"],
    "tucows": ["hover.com", "tucows.com", "hoverdns.com"],
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

    def __init__(
        self,
        reporter_email: str = "",
        *,
        provider_source: str = "origin",
        provider_label: str = "Hosting provider",
        platform_name: Optional[str] = None,
        display_name: Optional[str] = None,
    ):
        super().__init__()
        self.reporter_email = reporter_email
        self.provider_source = provider_source
        self.provider_label = provider_label
        if platform_name:
            self.platform_name = platform_name
        if display_name:
            self.display_name = display_name
        self._configured = True

    @staticmethod
    def _normalize_provider(provider: str) -> Optional[str]:
        if not provider:
            return None
        candidate = provider.strip().lower()
        if not candidate:
            return None
        for key in list(ABUSE_FORMS.keys()) + list(ABUSE_EMAILS.keys()):
            if key in candidate:
                return key
        return candidate

    def _detect_origin_provider(self, evidence: ReportEvidence) -> Optional[str]:
        provider = self._normalize_provider(evidence.hosting_provider or "")
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
        if "aws" in haystack or "cloudfront" in haystack or "amazonaws" in haystack:
            return "aws"

        return None

    def _detect_edge_provider(self, evidence: ReportEvidence) -> Optional[str]:
        infra = (evidence.analysis_json or {}).get("infrastructure") or {}
        provider = (
            (evidence.analysis_json or {}).get("edge_provider")
            or infra.get("edge_provider")
            or ""
        )
        return self._normalize_provider(provider)

    def _detect_dns_provider(self, evidence: ReportEvidence) -> Optional[str]:
        infra = (evidence.analysis_json or {}).get("infrastructure") or {}
        nameservers = infra.get("nameservers") or []
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        joined = " ".join([ns.lower() for ns in nameservers])
        if not joined:
            return None
        for provider, needles in DNS_PROVIDER_PATTERNS.items():
            if any(needle in joined for needle in needles):
                return provider
        return None

    def _detect_provider_from_evidence(self, evidence: ReportEvidence) -> Optional[str]:
        if self.provider_source == "edge":
            return self._detect_edge_provider(evidence)
        if self.provider_source == "dns":
            return self._detect_dns_provider(evidence)
        return self._detect_origin_provider(evidence)

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

        destination_url = form_url or (f"mailto:{email}" if email else "")

        notes = [
            f"Detected {self.provider_label}: {provider.upper()}",
            "Submit via the abuse form or email the abuse contact.",
        ]
        if not form_url and not email:
            notes.append("No specific abuse contact found; use the provider/ASN WHOIS abuse email.")

        return ManualSubmissionData(
            form_url=destination_url,
            reason=f"{self.provider_label}: {provider}",
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
                reason=f"{self.provider_label} not identified",
                fields=[
                    ManualSubmissionField(
                        name="url",
                        label="Phishing URL",
                        value=evidence.url,
                    )
                ],
                notes=[f"No {self.provider_label.lower()} identified from this evidence."],
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
