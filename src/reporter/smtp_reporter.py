"""SMTP email reporter for SeedBuster."""

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from typing import Optional

import aiosmtplib

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus, ConfigurationError
from .rdap import lookup_registrar_via_rdap
from .templates import ReportTemplates

logger = logging.getLogger(__name__)


# Known abuse email addresses
ABUSE_CONTACTS = {
    "digitalocean": "abuse@digitalocean.com",
    "cloudflare": "abuse@cloudflare.com",
    "namecheap": "abuse@namecheap.com",
    "godaddy": "abuse@godaddy.com",
    "google": "abuse@google.com",
    "amazon": "abuse@amazonaws.com",
    "microsoft": "abuse@microsoft.com",
    "ovh": "abuse@ovh.net",
    "hetzner": "abuse@hetzner.com",
    "vultr": "abuse@vultr.com",
    "linode": "abuse@linode.com",
    "hostinger": "abuse@hostinger.com",
}


class SMTPReporter(BaseReporter):
    """
    SMTP-based email reporter.

    Sends formatted abuse reports via email to hosting providers,
    registrars, and other abuse contacts.
    """

    platform_name = "smtp"
    platform_url = ""
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 10  # Be conservative with email

    def __init__(
        self,
        host: str,
        port: int = 587,
        username: str = "",
        password: str = "",
        from_email: str = "",
        use_tls: bool = True,
    ):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.use_tls = use_tls

        self._configured = bool(host and from_email)

    def is_configured(self) -> bool:
        return self._configured

    def get_abuse_contact(self, evidence: ReportEvidence) -> Optional[str]:
        """
        Determine abuse contact email based on evidence.

        Checks hosting provider and backend domains.
        """
        # Check hosting provider
        if evidence.hosting_provider:
            provider = evidence.hosting_provider.lower()
            for key, email in ABUSE_CONTACTS.items():
                if key in provider:
                    return email

        # Check backend domains for hosting patterns
        for domain in evidence.backend_domains:
            domain_lower = domain.lower()
            if "ondigitalocean.app" in domain_lower:
                return ABUSE_CONTACTS["digitalocean"]
            elif "cloudflare" in domain_lower:
                return ABUSE_CONTACTS["cloudflare"]
            elif "vercel" in domain_lower:
                return "abuse@vercel.com"
            elif "netlify" in domain_lower:
                return "abuse@netlify.com"
            elif "herokuapp" in domain_lower:
                return "abuse@salesforce.com"

        return None

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

    async def send_email(
        self,
        to_email: str,
        subject: str,
        body: str,
        attachments: list[Path] = None,
    ) -> bool:
        """
        Send an email via SMTP.

        Returns True if successful.
        """
        if not self._configured:
            raise ConfigurationError("SMTP not configured")

        msg = MIMEMultipart()
        msg["From"] = self.from_email
        msg["To"] = to_email
        msg["Subject"] = subject

        # Add body
        msg.attach(MIMEText(body, "plain"))

        # Add attachments
        if attachments:
            for filepath in attachments:
                if filepath and filepath.exists():
                    try:
                        with open(filepath, "rb") as f:
                            part = MIMEBase("application", "octet-stream")
                            part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header(
                            "Content-Disposition",
                            f"attachment; filename={filepath.name}",
                        )
                        msg.attach(part)
                    except Exception as e:
                        logger.warning(f"Failed to attach {filepath}: {e}")

        try:
            await aiosmtplib.send(
                msg,
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                start_tls=self.use_tls,
            )
            return True

        except aiosmtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed: {e}")
            raise ConfigurationError(f"SMTP authentication failed: {e}")

        except Exception as e:
            logger.exception(f"SMTP send failed: {e}")
            return False

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """
        Send abuse report via email.

        Automatically determines the appropriate abuse contact based on
        the evidence (hosting provider, backend domains, etc.).
        """
        # Validate evidence
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        # Determine abuse contact
        registrar_name: Optional[str] = None
        use_registrar_template = False
        abuse_email = self.get_abuse_contact(evidence)
        if not abuse_email:
            lookup = await lookup_registrar_via_rdap(evidence.domain)
            registrar_name = lookup.registrar_name
            abuse_email = lookup.abuse_email or self._match_known_abuse_email(registrar_name)
            if abuse_email:
                use_registrar_template = True
            else:
                detail = f"{lookup.error}: {lookup.rdap_url}" if lookup.error else f"RDAP: {lookup.rdap_url}"
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.SKIPPED,
                    message=f"Could not determine abuse contact email for this domain ({detail})",
                )

        # Generate appropriate report based on provider
        if use_registrar_template:
            report = ReportTemplates.registrar(
                evidence,
                reporter_email=self.from_email,
                registrar_name=registrar_name,
            )
        elif "digitalocean" in abuse_email:
            report = ReportTemplates.digitalocean(evidence, self.from_email)
        else:
            report = ReportTemplates.generic_email(evidence, self.from_email)

        # Collect attachments
        attachments: list[Path] = []
        if evidence.screenshot_path and evidence.screenshot_path.exists():
            attachments.append(evidence.screenshot_path)
        if evidence.html_path and evidence.html_path.exists():
            attachments.append(evidence.html_path)

        try:
            success = await self.send_email(
                to_email=abuse_email,
                subject=report["subject"],
                body=report["body"],
                attachments=attachments,
            )

            if success:
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.SUBMITTED,
                    message=f"Email sent to {abuse_email}",
                )
            else:
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.FAILED,
                    message="Email send failed",
                )

        except ConfigurationError as e:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=str(e),
            )

        except Exception as e:
            logger.exception("SMTP submission error")
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=f"Email failed: {e}",
            )

    async def submit_to_specific(
        self,
        evidence: ReportEvidence,
        to_email: str,
        template: str = "generic",
    ) -> ReportResult:
        """
        Send abuse report to a specific email address.

        Args:
            evidence: Report evidence
            to_email: Target email address
            template: Template to use (generic, digitalocean, registrar)
        """
        # Generate report based on template
        if template == "digitalocean":
            report = ReportTemplates.digitalocean(evidence, self.from_email)
        elif template == "registrar":
            report = ReportTemplates.registrar(evidence, self.from_email)
        else:
            report = ReportTemplates.generic_email(evidence, self.from_email)

        # Collect attachments
        attachments: list[Path] = []
        if evidence.screenshot_path and evidence.screenshot_path.exists():
            attachments.append(evidence.screenshot_path)
        if evidence.html_path and evidence.html_path.exists():
            attachments.append(evidence.html_path)

        try:
            success = await self.send_email(
                to_email=to_email,
                subject=report["subject"],
                body=report["body"],
                attachments=attachments,
            )

            if success:
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.SUBMITTED,
                    message=f"Email sent to {to_email}",
                )
            else:
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.FAILED,
                    message="Email send failed",
                )

        except Exception as e:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=f"Email failed: {e}",
            )
