"""APWG manual reporter for SeedBuster.

APWG primarily accepts phishing email submissions (ideally forwarded as an
attachment with full headers). This helper generates copy/paste instructions
for submitting the phishing URL and evidence when email artifacts are not
available.
"""

from __future__ import annotations

from .base import (
    BaseReporter,
    ManualSubmissionData,
    ManualSubmissionField,
    ReportEvidence,
    ReportResult,
    ReportStatus,
)


class APWGReporter(BaseReporter):
    """Anti-Phishing Working Group (APWG) manual reporting helper."""

    platform_name = "apwg"
    platform_url = "https://apwg.org/reportphishing"
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 60
    manual_only = True

    DESTINATION_EMAIL = "reportphishing@apwg.org"

    def __init__(self):
        super().__init__()
        self._configured = True

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        if evidence.scam_type == "crypto_doubler":
            subject = f"Fraud Report: {evidence.domain} - Crypto Doubler / Fake Giveaway"
        else:
            subject = f"Phishing Report: {evidence.domain} - Cryptocurrency Seed Phrase Theft"
        email_body = evidence.to_summary().strip()
        mailto_url = f"mailto:{self.DESTINATION_EMAIL}?subject={subject}"
        return ManualSubmissionData(
            form_url=mailto_url,
            reason="Email submission",
            fields=[
                ManualSubmissionField(
                    name="to",
                    label="Send email to",
                    value=self.DESTINATION_EMAIL,
                ),
                ManualSubmissionField(
                    name="subject",
                    label="Subject line",
                    value=subject,
                ),
                ManualSubmissionField(
                    name="body",
                    label="Email body",
                    value=email_body,
                    multiline=True,
                ),
            ],
            notes=[
                "Best practice: Forward the original phishing email as an attachment with full headers.",
                "If no email artifact is available, send the URL and evidence summary instead.",
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
        subject = next(
            (field.value for field in manual_data.fields if field.name == "subject"),
            f"Phishing Report: {evidence.domain}",
        )
        email_body = next(
            (field.value for field in manual_data.fields if field.name == "body"),
            evidence.to_summary().strip(),
        )

        body_lines = [
            "APWG Report Phishing (manual helper)",
            "",
            f"Destination: {self.DESTINATION_EMAIL}",
            "",
            "Preferred submission (best):",
            "- If you have the original phishing email, forward it as an attachment (with full headers).",
            "",
            "If you only have a URL/domain (no email artifact):",
            f"- Phishing URL: {evidence.url}",
            f"- Domain: {evidence.domain}",
            f"- Confidence: {evidence.confidence_score}%",
            "",
            "Evidence summary:",
            email_body,
            "",
            "Copy/paste email template:",
            f"To: {self.DESTINATION_EMAIL}",
            f"Subject: {subject}",
            "",
            email_body,
        ]

        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message="\n".join(body_lines).strip(),
            response_data={"manual_fields": manual_data.to_dict()},
        )
