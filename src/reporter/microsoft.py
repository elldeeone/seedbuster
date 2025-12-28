"""Microsoft phishing reporting helper for SeedBuster.

Microsoft provides a public "Report an unsafe site" flow (WDSI / SmartScreen).
Automation is unreliable due to dynamic pages and bot protections, so this
reporter generates manual submission instructions.
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


class MicrosoftReporter(BaseReporter):
    """Microsoft (WDSI/SmartScreen) manual reporting helper."""

    platform_name = "microsoft"
    platform_url = "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site"
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 60
    manual_only = True

    REPORT_URL = "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site"

    def __init__(self):
        super().__init__()
        self._configured = True

    def generate_manual_submission(self, evidence: ReportEvidence) -> ManualSubmissionData:
        details = evidence.to_summary().strip()
        return ManualSubmissionData(
            form_url=self.REPORT_URL,
            reason="Microsoft form (bot protection)",
            fields=[
                ManualSubmissionField(
                    name="url",
                    label="URL to report",
                    value=evidence.url,
                ),
                ManualSubmissionField(
                    name="category",
                    label="Suggested category",
                    value="phishing / unsafe site",
                ),
                ManualSubmissionField(
                    name="details",
                    label="Additional details",
                    value=details,
                    multiline=True,
                ),
            ],
            notes=[
                "Select 'Phishing' or 'Unsafe site' as the category.",
                "The form may require sign-in to Microsoft account.",
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
        details = next(
            (field.value for field in manual_data.fields if field.name == "details"),
            evidence.to_summary().strip(),
        )

        message = "\n".join([
            "Manual submission required (Microsoft):",
            self.REPORT_URL,
            "",
            "Suggested category: phishing / unsafe site",
            "",
            f"URL: {evidence.url}",
            "",
            "Copy/paste details:",
            details,
        ]).strip()

        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message=message,
            response_data={"manual_fields": manual_data.to_dict()},
        )
