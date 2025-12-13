"""Netcraft reporter for SeedBuster."""

import logging

import httpx

from .base import BaseReporter, ReportEvidence, ReportResult, ReportStatus

logger = logging.getLogger(__name__)


class NetcraftReporter(BaseReporter):
    """
    Netcraft phishing site reporter via API.

    Netcraft is a well-established anti-phishing service used by
    many browsers and security tools. No account required.
    """

    platform_name = "netcraft"
    platform_url = "https://report.netcraft.com"
    supports_evidence = True
    requires_api_key = False
    rate_limit_per_minute = 10

    API_URL = "https://report.netcraft.com/api/v3/report/urls"

    def __init__(self, reporter_email: str = ""):
        super().__init__()
        # Extract just the email address if in "Name <email>" format
        if "<" in reporter_email and ">" in reporter_email:
            self.reporter_email = reporter_email.split("<")[-1].rstrip(">")
        else:
            self.reporter_email = reporter_email
        self._configured = True  # Always available

    async def submit(self, evidence: ReportEvidence) -> ReportResult:
        """Submit URL to Netcraft via API."""
        # Validate evidence
        is_valid, error = self.validate_evidence(evidence)
        if not is_valid:
            return ReportResult(
                platform=self.platform_name,
                status=ReportStatus.FAILED,
                message=error,
            )

        # Build reason string
        reason_parts = [
            "Cryptocurrency seed phrase phishing site.",
            f"Confidence: {evidence.confidence_score}%",
        ]
        for r in evidence.detection_reasons[:3]:
            reason_parts.append(f"- {r}")
        reason_parts.append("Detected by SeedBuster.")
        reason = " ".join(reason_parts)

        # Build payload
        payload = {
            "urls": [
                {
                    "url": evidence.url,
                    "reason": reason,
                }
            ]
        }

        # Add email if configured
        if self.reporter_email:
            payload["email"] = self.reporter_email

        async with httpx.AsyncClient(timeout=30) as client:
            try:
                resp = await client.post(
                    self.API_URL,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "User-Agent": "SeedBuster/1.0 (anti-phishing tool)",
                    },
                )

                if resp.status_code in (200, 201, 202):
                    try:
                        result = resp.json()
                        uuid = result.get("uuid", "")
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.SUBMITTED,
                            report_id=uuid,
                            message="Submitted to Netcraft" + (f" (UUID: {uuid})" if uuid else ""),
                        )
                    except Exception:
                        return ReportResult(
                            platform=self.platform_name,
                            status=ReportStatus.SUBMITTED,
                            message="Submitted to Netcraft",
                        )

                elif resp.status_code == 400:
                    # Check for duplicate
                    try:
                        result = resp.json()
                        details = result.get("details", [])
                        if any("duplicate" in str(d).lower() for d in details):
                            return ReportResult(
                                platform=self.platform_name,
                                status=ReportStatus.DUPLICATE,
                                message="URL already reported to Netcraft",
                            )
                    except Exception:
                        pass
                    return ReportResult(
                        platform=self.platform_name,
                        status=ReportStatus.FAILED,
                        message=f"Bad request: {resp.text[:100]}",
                    )

                elif resp.status_code == 429:
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
                        message=f"Netcraft returned {resp.status_code}",
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
