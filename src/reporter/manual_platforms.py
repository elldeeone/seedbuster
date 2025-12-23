"""Manual-only reporters for popular providers (forms and abuse mailboxes)."""

from __future__ import annotations

from .base import (
    BaseReporter,
    ManualSubmissionData,
    ManualSubmissionField,
    ReportEvidence,
    ReportResult,
    ReportStatus,
)


def _basic_description(evidence: ReportEvidence, *, extra: str | None = None) -> str:
    """Build a short, portable description for manual submissions."""
    lines: list[str] = [
        f"URL: {evidence.url}",
        f"Domain: {evidence.domain}",
        f"Confidence: {evidence.confidence_score}%",
        "",
        "Detection reasons:",
    ]
    for reason in (evidence.detection_reasons or [])[:5]:
        lines.append(f"- {reason}")
    if extra:
        lines.extend(["", extra])
    return "\n".join(lines).strip()


class _SimpleFormReporter(BaseReporter):
    """Lightweight manual-only reporter with shared form/field structure."""

    manual_only = True
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 30

    def __init__(self, *, platform_name: str, form_url: str, notes: list[str], reason: str):
        super().__init__()
        self.platform_name = platform_name
        self.platform_url = form_url
        self._notes = notes
        self._reason = reason
        self._configured = True

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        description = _basic_description(evidence)
        return ManualSubmissionData(
            form_url=self.platform_url,
            reason=self._reason,
            fields=[
                ManualSubmissionField(name="url", label="URL to report", value=evidence.url),
                ManualSubmissionField(
                    name="details",
                    label="Details / evidence",
                    value=description,
                    multiline=True,
                ),
            ],
            notes=self._notes,
        )

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        manual_data = self.generate_manual_submission(evidence)
        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message=f"Manual submission required: {self.platform_url}",
            response_data={"manual_fields": manual_data.to_dict()},
        )


class _SimpleEmailReporter(BaseReporter):
    """Manual-only reporter that guides the user to send an email."""

    manual_only = True
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 60

    def __init__(self, *, platform_name: str, email: str, subject_prefix: str, notes: list[str]):
        super().__init__()
        self.platform_name = platform_name
        self.platform_url = f"mailto:{email}"
        self._email = email
        self._subject_prefix = subject_prefix
        self._notes = notes
        self._configured = True

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        description = _basic_description(evidence)
        subject = f"{self._subject_prefix} {evidence.domain}"
        return ManualSubmissionData(
            form_url=self.platform_url,
            reason="Email submission",
            fields=[
                ManualSubmissionField(name="to", label="Send email to", value=self._email),
                ManualSubmissionField(name="subject", label="Subject", value=subject),
                ManualSubmissionField(
                    name="body",
                    label="Email body",
                    value=description,
                    multiline=True,
                ),
            ],
            notes=self._notes,
        )

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        manual_data = self.generate_manual_submission(evidence)
        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message=f"Manual submission required: {self._email}",
            response_data={"manual_fields": manual_data.to_dict()},
        )


class AWSReporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="aws",
            form_url="https://support.aws.amazon.com/#/contacts/report-abuse",
            reason="AWS Trust & Safety form",
            notes=[
                "Include any AWS resource identifiers if visible (S3 bucket URL, CloudFront domain, EC2 IP).",
                "Select 'Phishing' as the abuse type.",
            ],
        )


class GCPReporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="gcp",
            form_url="https://support.google.com/code/contact/cloud_platform_report",
            reason="Google Cloud Platform abuse form",
            notes=[
                "If the site uses *.appspot.com or *.cloudfunctions.net include the full URL.",
                "Select 'Phishing' as the category.",
            ],
        )


class AzureReporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="azure",
            form_url="https://msrc.microsoft.com/report",
            reason="Microsoft Security Response Center",
            notes=[
                "Choose 'Abuse' or 'Phishing' when prompted.",
                "If you know the Azure resource (web app/site), include it in the details.",
            ],
        )


class VercelReporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="vercel",
            form_url="https://vercel.com/abuse",
            reason="Vercel abuse form",
            notes=[
                "If the domain uses *.vercel.app include the exact subdomain.",
                "Vercel typically responds quickly; include screenshots if available.",
            ],
        )


class NetlifyReporter(_SimpleEmailReporter):
    def __init__(self):
        super().__init__(
            platform_name="netlify",
            email="fraud@netlify.com",
            subject_prefix="Phishing report:",
            notes=[
                "Netlify prefers emails with the full phishing URL and a short description.",
                "Attach screenshots if possible.",
            ],
        )


class GoDaddyReporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="godaddy",
            form_url="https://supportcenter.godaddy.com/abusereport/phishing",
            reason="GoDaddy phishing report form",
            notes=[
                "Provide the full URL and describe the phishing content.",
                "If you know the GoDaddy customer number, include it (optional).",
            ],
        )


class NamecheapReporter(_SimpleEmailReporter):
    def __init__(self):
        super().__init__(
            platform_name="namecheap",
            email="abuse@namecheaphosting.com",
            subject_prefix="Phishing report:",
            notes=[
                "Include the full phishing URL and any evidence of credential harvesting.",
                "Namecheap accepts plain-text reports; attachments optional.",
            ],
        )


class PorkbunReporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="porkbun",
            form_url="https://porkbun.com/abuse",
            reason="Porkbun abuse form",
            notes=[
                "Include the phishing URL and a short description of the scam.",
                "If you know the registrant or hosting details, add them to the message.",
            ],
        )


class TelegramReporter(_SimpleEmailReporter):
    def __init__(self):
        super().__init__(
            platform_name="telegram",
            email="abuse@telegram.org",
            subject_prefix="Phishing / scam report:",
            notes=[
                "If reporting a bot, include the bot handle or invite link.",
                "Telegram also accepts reports via @notoscam bot (optional).",
            ],
        )


class DiscordReporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="discord",
            form_url="https://discord.com/safety/360044103651",
            reason="Discord Trust & Safety form",
            notes=[
                "If reporting a webhook, include the webhook URL.",
                "Add server ID/channel ID if applicable to help Trust & Safety locate the content.",
            ],
        )


class Quad9Reporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="quad9",
            form_url="https://quad9.net/contact/",
            reason="Quad9 threat blocking request",
            notes=[
                "Quad9 blocks malicious domains at the DNS layer; include the full domain.",
                "Describe the threat type as phishing; add any supporting evidence.",
            ],
        )
