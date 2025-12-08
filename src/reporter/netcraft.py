"""Netcraft reporter for SeedBuster."""

import logging
from typing import Optional

import httpx

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus

logger = logging.getLogger(__name__)


class NetcraftReporter(BaseReporter):
    """
    Netcraft phishing site reporter.

    Netcraft is a well-established anti-phishing service used by
    many browsers and security tools. No account required.

    Submission is via their web form API.
    """

    platform_name = "netcraft"
    platform_url = "https://report.netcraft.com"
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 10

    # Netcraft submission endpoint
    SUBMIT_URL = "https://report.netcraft.com/api/v3/report/urls"

    def __init__(self):
        super().__init__()
        self._configured = True  # Always available

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """Submit URL to Netcraft."""
        # Validate evidence
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        # Build reason string
        reasons = "\n".join(f"- {r}" for r in evidence.detection_reasons)
        comment = (
            f"Cryptocurrency seed phrase phishing site.\n"
            f"Confidence: {evidence.confidence_score}%\n\n"
            f"Detection reasons:\n{reasons}\n\n"
            f"Detected by SeedBuster anti-phishing tool."
        )

        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            try:
                # Netcraft's API accepts JSON
                payload = {
                    "urls": [evidence.url],
                    "reason": comment,
                }

                resp = await client.post(
                    self.SUBMIT_URL,
                    json=payload,
                    headers={
                        "User-Agent": "SeedBuster/1.0 (anti-phishing tool)",
                        "Content-Type": "application/json",
                    },
                )

                if resp.status_code in (200, 201, 202):
                    # Success
                    try:
                        result = resp.json()
                        report_uuid = result.get("uuid", "")
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.SUBMITTED,
                            report_id=report_uuid,
                            message=f"Submitted to Netcraft (UUID: {report_uuid})" if report_uuid else "Submitted to Netcraft",
                        )
                    except Exception:
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.SUBMITTED,
                            message="Submitted to Netcraft",
                        )

                elif resp.status_code == 409:
                    # Already reported
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.DUPLICATE,
                        message="URL already reported to Netcraft",
                    )

                elif resp.status_code == 429:
                    # Rate limited
                    retry_after = int(resp.headers.get("Retry-After", 60))
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.RATE_LIMITED,
                        message="Rate limited by Netcraft",
                        retry_after=retry_after,
                    )

                else:
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.FAILED,
                        message=f"Netcraft returned {resp.status_code}: {resp.text[:200]}",
                    )

            except httpx.TimeoutException:
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.FAILED,
                    message="Request timed out",
                )

            except Exception as e:
                logger.exception("Netcraft submission error")
                return ReportResult(
                    platform=self.platform_name,
                    status=ReportStatus.FAILED,
                    message=f"Submission failed: {e}",
                )
