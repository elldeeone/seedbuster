"""Registrar manual reporter for SeedBuster.

This reporter does not attempt automation. It performs a best-effort RDAP lookup
to identify the domain registrar, then provides an abuse email/form destination
and a copy/paste-ready email template.
"""

import logging
from typing import Optional

from ..utils.domains import registered_domain

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
    "tucows": "compliance@tucows.com",
    "dreamhost": "abuse@dreamhost.com",
    "instra": "legal@instra.com",
    "ultahost": "abuse@ultahost.com",
    "namesilo": "abuse@namesilo.com",
    "synergy wholesale": "abuse@synergywholesale.com",
}

REGISTRAR_ABUSE_FORMS: dict[str, str] = {
    "abovedomains": "https://www.above.com/contact.html",
    "above.com": "https://www.above.com/contact.html",
    "cloudflare": "https://abuse.cloudflare.com/",
    "dynadot": "https://www.dynadot.com/report-abuse",
    "godaddy": "https://supportcenter.godaddy.com/abusereport",
    "hostinger": "https://www.hostinger.com/report-abuse",
    "namesilo": "https://www.namesilo.com/report_abuse.php",
    "squarespace domains": "https://support.squarespace.com/hc/en-us/articles/11580957865869-Reporting-abuse",
    "tucows": "https://tucowsdomains.com/report-abuse/",
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

    def _reporter_email_address(self) -> str:
        raw = (self.reporter_email or "").strip()
        if "<" in raw and ">" in raw:
            raw = raw.split("<", 1)[1].split(">", 1)[0].strip()
        return raw

    def _reporter_name(self) -> str:
        raw = (self.reporter_email or "").strip()
        if "<" in raw and ">" in raw:
            return raw.split("<", 1)[0].strip().strip('"')
        return ""

    @staticmethod
    def _is_dynadot(registrar_name: Optional[str], abuse_form: Optional[str]) -> bool:
        if abuse_form and "dynadot.com/report-abuse" in abuse_form:
            return True
        return "dynadot" in (registrar_name or "").lower()

    def _build_dynadot_submission(
        self,
        evidence: ReportEvidence,
        *,
        registrar_name: Optional[str],
        abuse_form: str,
    ) -> ManualSubmissionData:
        reporter_email = self._reporter_email_address() or "(fill manually)"
        reporter_name = self._reporter_name() or "(fill manually)"
        domain_value = registered_domain(evidence.domain) or (evidence.domain or "").strip().lower()
        official_site = evidence.get_official_site() or "N/A"
        comments = evidence.to_summary().strip()

        fields: list[ManualSubmissionField] = [
            ManualSubmissionField(
                name="abuse_type",
                label="Abuse Type",
                value="Phishing",
            ),
            ManualSubmissionField(
                name="full_name",
                label="Full Name",
                value=reporter_name,
            ),
            ManualSubmissionField(
                name="email",
                label="Email Address",
                value=reporter_email,
            ),
            ManualSubmissionField(
                name="confirm_email",
                label="Confirm Email Address",
                value=reporter_email,
            ),
            ManualSubmissionField(
                name="phone",
                label="Phone Number (Optional)",
                value="",
            ),
            ManualSubmissionField(
                name="domain",
                label="Domain Name Involved",
                value=domain_value,
            ),
            ManualSubmissionField(
                name="official_site",
                label="Official Website",
                value=official_site,
            ),
            ManualSubmissionField(
                name="vpn_proxy",
                label="VPN/Proxy location(s) or user-agent(s)",
                value="N/A",
            ),
            ManualSubmissionField(
                name="full_path",
                label="Full Domain Path",
                value=evidence.url,
            ),
            ManualSubmissionField(
                name="comments",
                label="Comments",
                value=comments,
                multiline=True,
            ),
        ]

        notes = [
            "Select 'Phishing' as the abuse type (use 'Spam Abuse' if the report is email-based).",
            "Only one domain allowed; use the registrable domain.",
            "Enter 'N/A' for fields that do not apply.",
            "Attach screenshots/HTML evidence if available.",
        ]
        if registrar_name:
            notes.insert(0, f"Registrar: {registrar_name}")

        return ManualSubmissionData(
            form_url=abuse_form,
            reason=f"Registrar: {registrar_name or 'Dynadot'}",
            fields=fields,
            notes=notes,
        )

    def _build_manual_submission(
        self,
        evidence: ReportEvidence,
        *,
        registrar_name: Optional[str],
        abuse_email: Optional[str],
        abuse_form: Optional[str],
    ) -> ManualSubmissionData:
        if abuse_form and self._is_dynadot(registrar_name, abuse_form):
            return self._build_dynadot_submission(
                evidence,
                registrar_name=registrar_name,
                abuse_form=abuse_form,
            )

        template = ReportTemplates.registrar(
            evidence,
            reporter_email=self.reporter_email or "your-email@example.com",
            registrar_name=registrar_name,
        )

        fields: list[ManualSubmissionField] = [
            ManualSubmissionField(
                name="url",
                label="Phishing URL",
                value=evidence.url,
            ),
            ManualSubmissionField(
                name="domain",
                label="Domain",
                value=(evidence.domain or "").strip().lower(),
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

        destination_url = abuse_form or (f"mailto:{abuse_email}" if abuse_email else "")

        notes = []
        if registrar_name:
            notes.append(f"Registrar: {registrar_name}")
        if not abuse_email:
            notes.append("No abuse email found; search registrar support for contact.")

        return ManualSubmissionData(
            form_url=destination_url,
            reason=f"Registrar: {registrar_name or 'Unknown'}",
            fields=fields,
            notes=notes,
        )

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        registrar_name = None
        abuse_email = None
        abuse_form = None
        try:
            infra = (evidence.analysis_json or {}).get("infrastructure") or {}
            registrar_name = infra.get("registrar")
            abuse_email = infra.get("registrar_abuse_email")
        except Exception:
            pass
        abuse_email = abuse_email or self._match_known(registrar_name, REGISTRAR_ABUSE_EMAILS)
        abuse_form = self._match_known(registrar_name, REGISTRAR_ABUSE_FORMS)
        return self._build_manual_submission(
            evidence,
            registrar_name=registrar_name,
            abuse_email=abuse_email,
            abuse_form=abuse_form,
        )

    def generate_manual_submission_with_hints(
        self,
        evidence: ReportEvidence,
        *,
        registrar_name: Optional[str] = None,
        registrar_abuse_email: Optional[str] = None,
    ) -> ManualSubmissionData:
        abuse_email = registrar_abuse_email or self._match_known(registrar_name, REGISTRAR_ABUSE_EMAILS)
        abuse_form = self._match_known(registrar_name, REGISTRAR_ABUSE_FORMS)
        return self._build_manual_submission(
            evidence,
            registrar_name=registrar_name,
            abuse_email=abuse_email,
            abuse_form=abuse_form,
        )

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

        manual_data = self._build_manual_submission(
            evidence,
            registrar_name=registrar_name,
            abuse_email=abuse_email,
            abuse_form=abuse_form,
        )
        subject_value = next(
            (field.value for field in manual_data.fields if field.name == "subject"),
            "",
        )
        body_value = next(
            (field.value for field in manual_data.fields if field.name == "body"),
            "",
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
                f"Subject: {subject_value}",
                "",
                body_value.strip(),
                "",
            ])
        else:
            parts.extend([
                "No registrar abuse email found; search registrar support for an abuse contact.",
                "",
                f"Suggested email subject: {subject_value}",
                "",
                body_value.strip(),
                "",
            ])

        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message="\n".join(parts).strip(),
            response_data={"manual_fields": manual_data.to_dict()},
        )
