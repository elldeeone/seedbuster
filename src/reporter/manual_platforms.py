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


def _extract_seed_field_name(reasons: list[str]) -> str | None:
    """Extract seed phrase field name from detection reasons if present."""
    import re
    for reason in reasons or []:
        text = (reason or "").strip().lower()
        if "seed phrase" not in text and "mnemonic" not in text:
            continue
        match = re.search(r"'([^']+)'", reason or "")
        if match:
            return match.group(1).strip()
    return None


def _finalize_description(
    lines: list[str],
    evidence: ReportEvidence,
    *,
    extra: str | None = None,
) -> str:
    """Append shared evidence sections to a description."""
    impersonation = evidence.get_impersonation_lines()
    if impersonation:
        lines.append("")
        lines.append("IMPERSONATION INDICATORS:")
        for line in impersonation:
            lines.append(f"  - {line}")

    cleaned_reasons = evidence.get_filtered_reasons(max_items=4)
    if cleaned_reasons:
        lines.append("")
        lines.append("KEY EVIDENCE:")
        for reason in cleaned_reasons:
            lines.append(f"  - {reason}")

    backends = evidence.backend_domains or []
    if backends:
        lines.append("")
        lines.append("DATA SENT TO (backend servers):")
        for backend in backends[:3]:
            lines.append(f"  - {backend}")

    endpoints = evidence.suspicious_endpoints or []
    if endpoints and not backends:
        lines.append("")
        lines.append("SUSPICIOUS ENDPOINTS:")
        for endpoint in endpoints[:3]:
            lines.append(f"  - {endpoint}")

    if extra:
        lines.extend(["", extra])

    return "\n".join(lines).strip()


def _basic_description(evidence: ReportEvidence, *, extra: str | None = None) -> str:
    """Build a human-readable abuse report description with context."""
    description = evidence.to_summary().strip()
    if not extra:
        return description
    return f"{description}\n\n{extra}".strip()


def _basic_description_seed_phishing(
    evidence: ReportEvidence,
    *,
    seed_field: str | None = None,
    extra: str | None = None,
) -> str:
    """Build a human-readable report description for seed phrase phishing."""
    seed_field = seed_field or _extract_seed_field_name(evidence.detection_reasons)
    lines: list[str] = [
        "ACTION REQUESTED: Please suspend this phishing site.",
        "",
        "WHAT THIS SITE DOES:",
        "This site impersonates a cryptocurrency wallet and tricks users into",
        "entering their seed phrase (a 12 or 24-word recovery phrase). The seed",
        "phrase is the master key to a crypto wallet - once stolen, the attacker",
        "can immediately drain all funds. Theft is irreversible.",
        "",
        "PHISHING SITE DETAILS:",
        f"  URL: {evidence.url}",
        f"  Domain: {evidence.domain}",
        f"  Detected: {evidence.detected_at.strftime('%Y-%m-%d %H:%M UTC') if evidence.detected_at else 'Unknown'}",
    ]

    if seed_field:
        lines.append(f"  Seed phrase field name: '{seed_field}'")

    return _finalize_description(lines, evidence, extra=extra)


def _basic_description_fake_airdrop(
    evidence: ReportEvidence,
    *,
    extra: str | None = None,
) -> str:
    """Build a human-readable report description for fake airdrop scams."""
    lines: list[str] = [
        "ACTION REQUESTED: Please suspend this fraudulent airdrop site.",
        "",
        "WHAT THIS SITE DOES:",
        "This site impersonates a cryptocurrency project and promotes a fake",
        "airdrop/claim flow. It is designed to mislead users into unsafe actions",
        "that can result in loss of funds or account compromise.",
        "",
        "FRAUD SITE DETAILS:",
        f"  URL: {evidence.url}",
        f"  Domain: {evidence.domain}",
        f"  Detected: {evidence.detected_at.strftime('%Y-%m-%d %H:%M UTC') if evidence.detected_at else 'Unknown'}",
    ]

    return _finalize_description(lines, evidence, extra=extra)


def _basic_description_generic(
    evidence: ReportEvidence,
    *,
    extra: str | None = None,
) -> str:
    """Build a generic report description for crypto fraud/phishing."""
    lines: list[str] = [
        "ACTION REQUESTED: Please suspend this fraudulent site.",
        "",
        "WHAT THIS SITE DOES:",
        "This site hosts cryptocurrency-related fraud/phishing content intended",
        "to trick users into unsafe actions.",
        "",
        "SITE DETAILS:",
        f"  URL: {evidence.url}",
        f"  Domain: {evidence.domain}",
        f"  Detected: {evidence.detected_at.strftime('%Y-%m-%d %H:%M UTC') if evidence.detected_at else 'Unknown'}",
    ]

    return _finalize_description(lines, evidence, extra=extra)


def _basic_description_crypto_doubler(evidence: ReportEvidence, *, extra: str | None = None) -> str:
    """Build a human-readable report description for crypto doubler scams."""
    lines: list[str] = [
        "ACTION REQUESTED: Please suspend this fraudulent giveaway site.",
        "",
        "WHAT THIS SITE DOES:",
        "This site impersonates a cryptocurrency project and runs an",
        "advance-fee fraud scheme (\"crypto doubler\" / fake giveaway).",
        "It promises to multiply deposits (e.g., 2x/3x) but victims receive",
        "nothing back once funds are sent.",
        "",
        "FRAUD SITE DETAILS:",
        f"  URL: {evidence.url}",
        f"  Domain: {evidence.domain}",
        f"  Detected: {evidence.detected_at.strftime('%Y-%m-%d %H:%M UTC') if evidence.detected_at else 'Unknown'}",
    ]

    wallets = evidence.scammer_wallets or []
    if wallets:
        lines.append("")
        lines.append("SCAMMER WALLET ADDRESSES:")
        for wallet in wallets[:5]:
            lines.append(f"  - {wallet}")

    impersonation = evidence.get_impersonation_lines()
    if impersonation:
        lines.append("")
        lines.append("IMPERSONATION INDICATORS:")
        for line in impersonation:
            lines.append(f"  - {line}")

    cleaned_reasons = evidence.get_filtered_reasons(max_items=4)
    if cleaned_reasons:
        lines.append("")
        lines.append("KEY EVIDENCE:")
        for reason in cleaned_reasons:
            lines.append(f"  - {reason}")

    backends = evidence.backend_domains or []
    if backends:
        lines.append("")
        lines.append("DATA SENT TO (backend servers):")
        for backend in backends[:3]:
            lines.append(f"  - {backend}")

    endpoints = evidence.suspicious_endpoints or []
    if endpoints and not backends:
        lines.append("")
        lines.append("SUSPICIOUS ENDPOINTS:")
        for endpoint in endpoints[:3]:
            lines.append(f"  - {endpoint}")

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
        # Use more descriptive subject that conveys urgency
        prefix = self._subject_prefix
        scam_type = evidence.resolve_scam_type()
        if scam_type == "crypto_doubler":
            if "phishing" in prefix.lower():
                prefix = prefix.replace("Phishing", "Fraud").replace("phishing", "fraud")
            subject_suffix = "Crypto Doubler / Fake Giveaway Fraud"
        elif scam_type == "fake_airdrop":
            if "phishing" in prefix.lower():
                prefix = prefix.replace("Phishing", "Fraud").replace("phishing", "fraud")
            subject_suffix = "Fake Airdrop / Claim Fraud"
        elif scam_type == "seed_phishing" or _extract_seed_field_name(evidence.detection_reasons):
            subject_suffix = "Cryptocurrency Seed Phrase Theft"
        else:
            subject_suffix = "Cryptocurrency Fraud"
        subject = f"{prefix} {evidence.domain} - {subject_suffix}"
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
            form_url="https://repost.aws/knowledge-center/report-aws-abuse",
            reason="AWS abuse reporting guidance",
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
            form_url="https://msrc.microsoft.com/report/abuse",
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


class NetlifyReporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="netlify",
            form_url="https://www.netlify.com/support/?topic=Report+Fraud+or+Abuse",
            reason="Netlify support form (Report Fraud or Abuse)",
            notes=[
                "Select the 'Report Fraud or Abuse' topic in the form.",
                "Include the full phishing URL and a short description.",
                "Attach screenshots if possible.",
            ],
        )


class GoDaddyReporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="godaddy",
            form_url="https://supportcenter.godaddy.com/abusereport",
            reason="GoDaddy abuse report form",
            notes=[
                "Provide the full URL and describe the phishing content.",
                "If you know the GoDaddy customer number, include it (optional).",
            ],
        )


class NamecheapReporter(_SimpleEmailReporter):
    def __init__(self):
        super().__init__(
            platform_name="namecheap",
            email="abuse@namecheap.com",
            subject_prefix="Phishing report:",
            notes=[
                "For domain abuse: abuse@namecheap.com",
                "Include the full phishing URL and evidence of credential harvesting.",
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
            form_url="https://support.discord.com/hc/en-us/requests/new?ticket_form_id=360000029731",
            reason="Discord Trust & Safety",
            notes=[
                "Discord now primarily uses in-app reporting. For webhooks, use their support form.",
                "If reporting a webhook, include the full webhook URL.",
                "Add server ID/channel ID if applicable to help locate the content.",
                "For phishing sites using Discord webhooks to exfiltrate data, mention this clearly.",
            ],
        )


class GoogleDomainsReporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="google_domains",
            form_url="https://support.squarespace.com/hc/en-us/articles/11580957865869-Reporting-abuse",
            reason="Squarespace Domains abuse reporting",
            notes=[
                "Use the abuse report web form linked from the Reporting abuse page.",
                "Include the full domain and any evidence of credential harvesting.",
            ],
        )
        self.platform_display_name = "Squarespace Domains"


class TucowsReporter(_SimpleFormReporter):
    def __init__(self):
        super().__init__(
            platform_name="tucows",
            form_url="https://tucowsdomains.com/report-abuse/",
            reason="Tucows/Hover abuse form",
            notes=[
                "Tucows is the registrar for Hover and other resellers; include full domain.",
                "If you know the reseller, include it in the details (optional).",
            ],
        )


class NjallaReporter(BaseReporter):
    """Manual helper for Njalla-hosted/nameserved domains via their contact form."""

    manual_only = True
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 30

    def __init__(self):
        super().__init__()
        self.platform_name = "njalla"
        self.platform_url = "https://njal.la/contact/"
        self._configured = True

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        description = _basic_description(evidence)
        return ManualSubmissionData(
            form_url=self.platform_url,
            reason="Njalla contact form",
            fields=[
                ManualSubmissionField(name="url", label="URL to report", value=evidence.url),
                ManualSubmissionField(
                    name="subject",
                    label="Subject",
                    value=f"Abuse report: {evidence.domain}",
                ),
                ManualSubmissionField(
                    name="details",
                    label="Details / evidence",
                    value=description,
                    multiline=True,
                ),
            ],
            notes=[
                "Njalla's public site exposes a general contact form (https://njal.la/contact/) for all requests.",
                "Include your email in the form and paste the details above into the message field.",
            ],
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


class RenderReporter(_SimpleEmailReporter):
    def __init__(self):
        super().__init__(
            platform_name="render",
            email="abuse@render.com",
            subject_prefix="Phishing report:",
            notes=[
                "Include the hosted domain/app URL and brief description of the phishing content.",
            ],
        )


class FlyReporter(_SimpleEmailReporter):
    def __init__(self):
        super().__init__(
            platform_name="fly_io",
            email="abuse@fly.io",
            subject_prefix="Phishing report:",
            notes=[
                "Include the fly.dev hostname or custom domain; add evidence of phishing.",
            ],
        )


class RailwayReporter(_SimpleEmailReporter):
    def __init__(self):
        super().__init__(
            platform_name="railway",
            email="abuse@railway.app",
            subject_prefix="Phishing report:",
            notes=[
                "Include the project URL/hostname if known; describe the phishing behavior.",
            ],
        )
