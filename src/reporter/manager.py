"""Report manager for coordinating abuse reports across platforms."""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from .base import (
    BaseReporter,
    ReportEvidence,
    ReportResult,
    ReportStatus,
    ReporterError,
)
from .rate_limiter import get_rate_limiter

if TYPE_CHECKING:
    from ..storage.database import Database
    from ..storage.evidence import EvidenceStore

logger = logging.getLogger(__name__)


class ReportManager:
    """
    Manages multi-platform abuse reporting.

    Coordinates reporters, handles rate limiting, tracks report status
    in database, and provides evidence packaging.
    """

    def __init__(
        self,
        database: "Database",
        evidence_store: "EvidenceStore",
        smtp_config: Optional[dict] = None,
        phishtank_api_key: Optional[str] = None,
        resend_api_key: Optional[str] = None,
        reporter_email: str = "",
    ):
        self.database = database
        self.evidence_store = evidence_store
        self.smtp_config = smtp_config or {}
        self.phishtank_api_key = phishtank_api_key
        self.resend_api_key = resend_api_key
        self.reporter_email = reporter_email

        self.reporters: dict[str, BaseReporter] = {}
        self._init_reporters()

    def _init_reporters(self):
        """Initialize available reporters based on configuration."""
        # Import here to avoid circular imports
        from .phishtank import PhishTankReporter
        from .smtp_reporter import SMTPReporter
        from .cloudflare import CloudflareReporter
        from .google_form import GoogleFormReporter
        from .netcraft import NetcraftReporter

        # PhishTank (requires login, registration currently disabled)
        self.reporters["phishtank"] = PhishTankReporter(
            api_key=self.phishtank_api_key
        )
        logger.info("Initialized PhishTank reporter (note: requires login)")

        # Google Safe Browsing form (always available, free)
        self.reporters["google"] = GoogleFormReporter()
        logger.info("Initialized Google Safe Browsing reporter")

        # Cloudflare abuse form (always available)
        self.reporters["cloudflare"] = CloudflareReporter()
        logger.info("Initialized Cloudflare reporter")

        # Netcraft (always available, no account needed)
        self.reporters["netcraft"] = NetcraftReporter()
        logger.info("Initialized Netcraft reporter")

        # Resend email reporter (if API key configured)
        if self.resend_api_key:
            from .resend_reporter import ResendReporter
            self.reporters["resend"] = ResendReporter(
                api_key=self.resend_api_key,
                from_email=self.reporter_email or "SeedBuster <onboarding@resend.dev>",
            )
            logger.info("Initialized Resend email reporter")

        # SMTP reporter (if configured)
        if self.smtp_config.get("host"):
            self.reporters["smtp"] = SMTPReporter(
                host=self.smtp_config["host"],
                port=self.smtp_config.get("port", 587),
                username=self.smtp_config.get("username", ""),
                password=self.smtp_config.get("password", ""),
                from_email=self.smtp_config.get("from_email", self.reporter_email),
            )
            logger.info("Initialized SMTP reporter")

    def get_available_platforms(self) -> list[str]:
        """Get list of available/configured platforms."""
        return [
            name
            for name, reporter in self.reporters.items()
            if reporter.is_configured()
        ]

    async def build_evidence(
        self,
        domain_id: int,
        domain: str,
    ) -> Optional[ReportEvidence]:
        """
        Build evidence package from stored analysis data.

        Args:
            domain_id: Database ID of the domain
            domain: Domain name

        Returns:
            ReportEvidence or None if domain not found
        """
        # Get domain data from database
        domain_data = await self.database.get_domain_by_id(domain_id)
        if not domain_data:
            logger.warning(f"Domain not found: {domain_id}")
            return None

        # Get evidence paths
        evidence_dir = self.evidence_store.get_evidence_path(domain)

        # Load analysis JSON if available
        analysis_json = {}
        analysis_path = self.evidence_store.get_analysis_path(domain)
        if analysis_path and analysis_path.exists():
            analysis_json = self.evidence_store.load_analysis(domain) or {}

        # Extract detection reasons from analysis
        detection_reasons = analysis_json.get("reasons", [])
        if not detection_reasons and domain_data.get("reasons"):
            # Try to parse from database
            import json
            try:
                detection_reasons = json.loads(domain_data["reasons"])
            except (json.JSONDecodeError, TypeError):
                detection_reasons = []

        # Build evidence
        evidence = ReportEvidence(
            domain=domain,
            url=f"https://{domain}",
            detected_at=datetime.fromisoformat(
                domain_data.get("first_seen", datetime.now().isoformat())
            ),
            confidence_score=domain_data.get("analysis_score", 0),
            detection_reasons=detection_reasons,
            suspicious_endpoints=analysis_json.get("suspicious_endpoints", []),
            screenshot_path=self.evidence_store.get_screenshot_path(domain),
            html_path=evidence_dir / "page.html" if evidence_dir else None,
            analysis_path=analysis_path,
            analysis_json=analysis_json,
            backend_domains=analysis_json.get("backend_domains", []),
            api_keys_found=analysis_json.get("api_keys_found", []),
            hosting_provider=analysis_json.get("hosting_provider"),
        )

        return evidence

    async def report_domain(
        self,
        domain_id: int,
        domain: str,
        platforms: Optional[list[str]] = None,
    ) -> dict[str, ReportResult]:
        """
        Submit reports to multiple platforms.

        Args:
            domain_id: Database ID of the domain
            domain: Domain name
            platforms: List of platforms to report to (None = all configured)

        Returns:
            Dict mapping platform name to ReportResult
        """
        # Build evidence package
        evidence = await self.build_evidence(domain_id, domain)
        if not evidence:
            return {
                "error": ReportResult(
                    platform="manager",
                    status=ReportStatus.FAILED,
                    message=f"Could not build evidence for domain {domain}",
                )
            }

        # Determine platforms to report to
        if platforms is None:
            platforms = self.get_available_platforms()
        else:
            # Filter to only available platforms
            platforms = [p for p in platforms if p in self.reporters]

        if not platforms:
            return {
                "error": ReportResult(
                    platform="manager",
                    status=ReportStatus.FAILED,
                    message="No platforms available for reporting",
                )
            }

        # Submit to each platform
        results: dict[str, ReportResult] = {}

        for platform in platforms:
            reporter = self.reporters[platform]

            # Check rate limit
            limiter = get_rate_limiter(
                platform,
                reporter.rate_limit_per_minute,
            )

            if not await limiter.acquire(timeout=30):
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.RATE_LIMITED,
                    message="Rate limit exceeded",
                    retry_after=int(limiter.wait_time()),
                )
                continue

            try:
                # Create pending report in database
                report_id = await self.database.add_report(
                    domain_id=domain_id,
                    platform=platform,
                    status="pending",
                )

                # Submit report
                result = await reporter.submit(evidence)
                result.report_id = str(report_id)
                results[platform] = result

                # Update database
                await self.database.update_report(
                    report_id=report_id,
                    status=result.status.value,
                    response=result.message,
                )

                logger.info(
                    f"Report submitted to {platform}: {result.status.value}"
                )

            except ReporterError as e:
                logger.error(f"Reporter error for {platform}: {e}")
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.FAILED,
                    message=str(e),
                )

            except Exception as e:
                logger.exception(f"Unexpected error reporting to {platform}")
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.FAILED,
                    message=f"Unexpected error: {e}",
                )

        return results

    async def get_report_status(self, domain_id: int) -> list[dict]:
        """
        Get all report statuses for a domain.

        Returns list of report records from database.
        """
        return await self.database.get_reports_for_domain(domain_id)

    async def get_pending_approvals(self) -> list[dict]:
        """Get domains awaiting report approval."""
        return await self.database.get_pending_reports()

    async def approve_report(self, domain_id: int, domain: str) -> dict[str, ReportResult]:
        """
        Approve and submit reports for a domain.

        Called when user clicks "Approve" in Telegram.
        """
        return await self.report_domain(domain_id, domain)

    async def reject_report(self, domain_id: int, reason: str = "false_positive"):
        """
        Reject a report (mark as false positive).

        Updates domain status in database.
        """
        await self.database.update_domain_status(
            domain_id,
            status="false_positive",
            verdict="benign",
        )
        logger.info(f"Report rejected for domain {domain_id}: {reason}")

    def format_results_summary(self, results: dict[str, ReportResult]) -> str:
        """Format report results for display."""
        lines = ["Report Results:"]

        for platform, result in results.items():
            status_emoji = {
                ReportStatus.SUBMITTED: "✅",
                ReportStatus.CONFIRMED: "✅",
                ReportStatus.PENDING: "⏳",
                ReportStatus.FAILED: "❌",
                ReportStatus.RATE_LIMITED: "⏱️",
                ReportStatus.DUPLICATE: "🔄",
                ReportStatus.REJECTED: "🚫",
            }.get(result.status, "❓")

            line = f"  {status_emoji} {platform}: {result.status.value}"
            if result.message:
                line += f" - {result.message[:50]}"
            lines.append(line)

        return "\n".join(lines)
