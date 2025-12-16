"""Registrar manual reporter for SeedBuster.

This reporter does not attempt automation. It performs a best-effort RDAP lookup
to identify the domain registrar, then provides an abuse email/form destination
and a copy/paste-ready email template.
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
from .rdap import lookup_registrar_via_rdap
from .templates import ReportTemplates

logger = logging.getLogger(__name__)


# Registrar abuse destinations (best-effort).
REGISTRAR_ABUSE_EMAILS: dict[str, str] = {
    "namecheap": "abuse@namecheap.com",
    "godaddy": "abuse@godaddy.com",
    "hostinger": "abuse@hostinger.com",
}

REGISTRAR_ABUSE_FORMS: dict[str, str] = {
    # Some registrars prefer web forms; keep this sparse unless confirmed.
}


class RegistrarReporter(BaseReporter):
    """Registrar manual reporting helper (RDAP-based)."""

    platform_name = "registrar"
    platform_url = "https://rdap.org/"
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 30
    manual_only = True

    def __init__(self, reporter_email: str = ""):
        super().__init__()
        self.reporter_email = reporter_email
        self._configured = True

    @staticmethod
    def _normalize_key(value: str) -> str:
        return (value or "").strip().lower()

    @classmethod
    def _match_known(cls, registrar_name: Optional[str], mapping: dict[str, str]) -> Optional[str]:
        """Return a mapped contact/form URL when registrar_name contains a known key."""
        key = cls._normalize_key(registrar_name or "")
        if not key:
            return None
        for needle, dest in mapping.items():
            if needle in key:
                return dest
        return None

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        domain = (evidence.domain or "").strip().lower()
        if not domain:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.SKIPPED,
                message="No domain available for RDAP lookup",
            )

        lookup = await lookup_registrar_via_rdap(domain)
        rdap_url = lookup.rdap_url
        if lookup.error:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.SKIPPED,
                message=f"{lookup.error}: {rdap_url}",
            )

        registrar_name = lookup.registrar_name
        abuse_email = lookup.abuse_email or self._match_known(registrar_name, REGISTRAR_ABUSE_EMAILS)
        abuse_form = self._match_known(registrar_name, REGISTRAR_ABUSE_FORMS)

        if not registrar_name and not abuse_email and not abuse_form:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.SKIPPED,
                message=f"Registrar not found via RDAP: {rdap_url}",
            )

        template = ReportTemplates.registrar(
            evidence,
            reporter_email=self.reporter_email or "your-email@example.com",
            registrar_name=registrar_name,
        )

        # Build structured data for the new UI
        fields: list[ManualSubmissionField] = [
            ManualSubmissionField(
                name="url",
                label="Phishing URL",
                value=evidence.url,
            ),
            ManualSubmissionField(
                name="domain",
                label="Domain",
                value=domain,
            ),
        ]

        if abuse_email:
            fields.extend([
                ManualSubmissionField(
                    name="to",
                    label="Send email to",
                    value=abuse_email,
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
        else:
            fields.extend([
                ManualSubmissionField(
                    name="subject",
                    label="Suggested subject",
                    value=template["subject"],
                ),
                ManualSubmissionField(
                    name="body",
                    label="Email body",
                    value=template["body"].strip(),
                    multiline=True,
                ),
            ])

        # Determine the best destination URL
        destination_url = abuse_form or (f"mailto:{abuse_email}" if abuse_email else "")

        notes = []
        if registrar_name:
            notes.append(f"Registrar: {registrar_name}")
        if not abuse_email:
            notes.append("No abuse email found; search registrar support for contact.")

        manual_data = ManualSubmissionData(
            form_url=destination_url,
            reason=f"Registrar: {registrar_name or 'Unknown'}",
            fields=fields,
            notes=notes,
        )

        # Build plain text message for backwards compatibility
        parts: list[str] = []
        if registrar_name:
            parts.append(f"Registrar detected: {registrar_name}")
            parts.append("")

        if abuse_form:
            parts.extend([
                f"Manual submission (web form): {abuse_form}",
                "",
            ])

        if abuse_email:
            parts.extend([
                f"Manual submission (email): {abuse_email}",
                "",
                f"Subject: {template['subject']}",
                "",
                template["body"].strip(),
                "",
            ])
        else:
            parts.extend([
                "No registrar abuse email found; search registrar support for an abuse contact.",
                "",
                f"Suggested email subject: {template['subject']}",
                "",
                template["body"].strip(),
                "",
            ])

        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message="\n".join(parts).strip(),
            response_data={"manual_fields": manual_data.to_dict()},
        )
