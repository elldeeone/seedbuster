"""APWG manual reporter for SeedBuster.

APWG primarily accepts phishing email submissions (ideally forwarded as an
attachment with full headers). This helper generates copy/paste instructions
for submitting the phishing URL and evidence when email artifacts are not
available.
"""

from __future__ import annotations

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus


class APWGReporter(BaseReporter):
    """Anti-Phishing Working Group (APWG) manual reporting helper."""

    platform_name = "apwg"
    platform_url = "https://apwg.org/reportphishing"
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 60

    DESTINATION_EMAIL = "reportphishing@apwg.org"

    def __init__(self):
        super().__init__()
        self._configured = True

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        subject = f"Phishing Report: {evidence.domain}"
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
            evidence.to_summary().strip(),
            "",
            "Copy/paste email template:",
            f"To: {self.DESTINATION_EMAIL}",
            f"Subject: {subject}",
            "",
            f"{evidence.to_summary().strip()}",
        ]

        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message="\n".join(body_lines).strip(),
        )

