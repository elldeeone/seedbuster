"""Report manager for coordinating abuse reports across platforms."""

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

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

    @staticmethod
    def _ensure_url(target: str) -> str:
        """Ensure a scheme is present so urlparse works predictably."""
        value = (target or "").strip()
        if not value:
            return ""
        if value.startswith(("http://", "https://")):
            return value
        return f"https://{value}"

    @classmethod
    def _extract_hostname(cls, target: str) -> str:
        """Extract hostname from a target that may include path/query/fragment."""
        parsed = urlparse(cls._ensure_url(target))
        return (parsed.hostname or "").strip().lower()

    @classmethod
    def _extract_hostnames_from_endpoints(cls, endpoints: list[object]) -> list[str]:
        """Extract unique hostnames from a list of URL-ish strings."""
        seen: set[str] = set()
        hosts: list[str] = []
        for item in endpoints or []:
            if not isinstance(item, str):
                continue
            raw = item.strip()
            if not raw:
                continue
            host = cls._extract_hostname(raw)
            if not host:
                continue
            if host in seen:
                continue
            seen.add(host)
            hosts.append(host)
        return hosts

    @staticmethod
    def _extract_api_key_indicators(reasons: list[object]) -> list[str]:
        """Extract API-key related indicators from reasons for reporting context."""
        found: list[str] = []
        seen: set[str] = set()
        for reason in reasons or []:
            if not isinstance(reason, str):
                continue
            lower = reason.lower()
            if "api key" not in lower and "apikey" not in lower:
                continue
            entry = reason.strip()
            if not entry or entry in seen:
                continue
            seen.add(entry)
            found.append(entry)
        return found

    @staticmethod
    def _is_timestamp_due(timestamp: str | None) -> bool:
        """Return True if a timestamp is missing or not in the future."""
        if not timestamp:
            return True
        value = timestamp.strip()
        if not value:
            return True
        try:
            # SQLite may store either "YYYY-MM-DD HH:MM:SS" or ISO strings.
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except Exception:
            return True
        # Compare naive timestamps in UTC-ish space (best-effort).
        if dt.tzinfo is None:
            return dt <= datetime.utcnow()
        return dt <= datetime.now(dt.tzinfo)

    @staticmethod
    def _build_manual_instructions_text(
        platform: str, evidence: ReportEvidence, result: ReportResult
    ) -> str:
        """Build a text file containing manual reporting instructions."""
        message = (result.message or "").strip()
        lines = [
            "SeedBuster Manual Report Instructions",
            f"Platform: {platform}",
            "",
        ]
        if message:
            lines.extend(["Platform Notes:", message, ""])
        lines.extend(["Evidence Summary:", evidence.to_summary().strip(), ""])
        return "\n".join(lines).strip() + "\n"

    async def retry_due_reports(self, *, limit: int = 20) -> list[ReportResult]:
        """
        Retry rate-limited reports that are due.

        This only retries reports in `rate_limited` status whose `next_attempt_at`
        is due (or missing). Pending/manual-required reports are not retried.
        """
        due = await self.database.get_due_retry_reports(limit=limit)
        if not due:
            return []

        attempted: list[ReportResult] = []

        for row in due:
            try:
                report_id = int(row["id"])
                domain_id = int(row["domain_id"])
                platform = str(row.get("platform") or "").strip().lower()
                domain = str(row.get("domain") or "").strip()

                reporter = self.reporters.get(platform)
                if not reporter or not reporter.is_configured():
                    result = ReportResult(
                        platform=platform or "unknown",
                        status=ReportStatus.FAILED,
                        report_id=str(report_id),
                        message="Reporter not configured",
                        response_data={"domain_id": domain_id, "domain": domain},
                    )
                    attempted.append(result)
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                    )
                    continue

                # Respect enabled_platforms selection.
                if self.enabled_platforms is not None and platform not in self.enabled_platforms:
                    continue

                evidence = await self.build_evidence(domain_id=domain_id, domain=domain)
                if not evidence:
                    result = ReportResult(
                        platform=platform,
                        status=ReportStatus.FAILED,
                        report_id=str(report_id),
                        message="Could not build evidence",
                        response_data={"domain_id": domain_id, "domain": domain},
                    )
                    attempted.append(result)
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                    )
                    continue

                limiter = get_rate_limiter(platform, reporter.rate_limit_per_minute)
                if not await limiter.acquire(timeout=5):
                    retry_after = max(30, int(limiter.wait_time() or 60))
                    msg = f"Rate limit exceeded; retry scheduled in {retry_after}s"
                    result = ReportResult(
                        platform=platform,
                        status=ReportStatus.RATE_LIMITED,
                        report_id=str(report_id),
                        message=msg,
                        retry_after=retry_after,
                        response_data={"domain_id": domain_id, "domain": domain},
                    )
                    attempted.append(result)
                    await self.database.update_report(
                        report_id=report_id,
                        status=result.status.value,
                        response=result.message,
                        retry_after=retry_after,
                    )
                    continue

                result = await reporter.submit(evidence)
                result.report_id = str(report_id)
                metadata = {"domain_id": domain_id, "domain": domain}
                if result.response_data is None:
                    result.response_data = metadata
                else:
                    try:
                        result.response_data = {**result.response_data, **metadata}
                    except Exception:
                        result.response_data = metadata
                attempted.append(result)

                if result.status == ReportStatus.MANUAL_REQUIRED:
                    try:
                        content = self._build_manual_instructions_text(platform, evidence, result)
                        await self.evidence_store.save_report_instructions(domain, platform, content)
                    except Exception as e:
                        logger.warning(f"Failed to save manual report instructions for {domain} ({platform}): {e}")

                await self.database.update_report(
                    report_id=report_id,
                    status=result.status.value,
                    response=result.message,
                    retry_after=result.retry_after,
                )

                await self._mark_domain_reported_if_needed(domain_id, {platform: result})

            except Exception as e:
                logger.exception("Retry reporting failed")
                # Best-effort: keep report in rate_limited so it can be retried.
                try:
                    report_id = int(row.get("id") or 0)
                    if report_id:
                        await self.database.update_report(
                            report_id=report_id,
                            status=ReportStatus.RATE_LIMITED.value,
                            response=f"Retry worker error: {e}",
                            retry_after=300,
                        )
                except Exception:
                    pass

        return attempted

    def __init__(
        self,
        database: "Database",
        evidence_store: "EvidenceStore",
        smtp_config: Optional[dict] = None,
        phishtank_api_key: Optional[str] = None,
        resend_api_key: Optional[str] = None,
        resend_from_email: Optional[str] = None,
        reporter_email: str = "",
        enabled_platforms: Optional[list[str]] = None,
    ):
        self.database = database
        self.evidence_store = evidence_store
        self.smtp_config = smtp_config or {}
        self.phishtank_api_key = phishtank_api_key
        self.resend_api_key = resend_api_key
        self.resend_from_email = resend_from_email
        self.reporter_email = reporter_email
        self.enabled_platforms = set(enabled_platforms) if enabled_platforms is not None else None

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
        from .hosting_provider import HostingProviderReporter

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
        self.reporters["netcraft"] = NetcraftReporter(
            reporter_email=self.resend_from_email or self.reporter_email or ""
        )
        logger.info("Initialized Netcraft reporter")

        # Hosting provider manual helper (opt-in via REPORT_PLATFORMS)
        self.reporters["hosting_provider"] = HostingProviderReporter(
            reporter_email=self.resend_from_email or self.reporter_email or ""
        )
        logger.info("Initialized hosting provider manual reporter")

        # Resend email reporter (if API key configured)
        if self.resend_api_key:
            from .resend_reporter import ResendReporter
            self.reporters["resend"] = ResendReporter(
                api_key=self.resend_api_key,
                from_email=self.resend_from_email or self.reporter_email or "SeedBuster <onboarding@resend.dev>",
            )
            logger.info(f"Initialized Resend email reporter (from: {self.resend_from_email or self.reporter_email})")

        # DigitalOcean form reporter (if we have reporter email for form submission)
        reporter_email = self.resend_from_email or self.reporter_email
        if reporter_email:
            from .digitalocean import DigitalOceanReporter
            self.reporters["digitalocean"] = DigitalOceanReporter(
                reporter_email=reporter_email.split("<")[-1].rstrip(">") if "<" in reporter_email else reporter_email,
                reporter_name="Kaspa Security",
            )
            logger.info("Initialized DigitalOcean form reporter (Playwright)")

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
        platforms = [
            name
            for name, reporter in self.reporters.items()
            if reporter.is_configured()
        ]
        if self.enabled_platforms is not None:
            platforms = [p for p in platforms if p in self.enabled_platforms]
        return platforms

    async def ensure_pending_reports(self, domain_id: int, platforms: Optional[list[str]] = None) -> None:
        """
        Ensure there is a pending (awaiting approval) report row per platform.

        This is used when reporting requires manual approval so `/report <id> status`
        can show per-platform pending status before any submissions are attempted.
        """
        if platforms is None:
            platforms = self.get_available_platforms()
        if not platforms:
            return

        existing = await self.database.get_reports_for_domain(domain_id)
        existing_platforms = {str(r.get("platform") or "").strip().lower() for r in existing}

        for platform in platforms:
            key = (platform or "").strip().lower()
            if not key or key in existing_platforms:
                continue
            await self.database.add_report(
                domain_id=domain_id,
                platform=key,
                status=ReportStatus.PENDING.value,
            )

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
        detection_reasons = analysis_json.get("reasons") or []
        if not detection_reasons:
            verdict_reasons = domain_data.get("verdict_reasons") or ""
            detection_reasons = [r.strip() for r in verdict_reasons.splitlines() if r.strip()]

        # Build evidence
        target = (domain or "").strip()
        hostname = self._extract_hostname(target) or target.lower()

        # Prefer the final URL from analysis if available (may include redirects to kit path).
        final_url = (analysis_json.get("final_url") or "").strip()
        report_url = final_url or self._ensure_url(target)

        suspicious_endpoints = analysis_json.get("suspicious_endpoints", []) or []

        backend_domains = analysis_json.get("backend_domains")
        if not backend_domains:
            backend_domains = self._extract_hostnames_from_endpoints(suspicious_endpoints)

        api_keys_found = analysis_json.get("api_keys_found")
        if not api_keys_found:
            api_keys_found = self._extract_api_key_indicators(detection_reasons)

        hosting_provider = analysis_json.get("hosting_provider")
        if not hosting_provider:
            hosting_provider = (analysis_json.get("infrastructure") or {}).get("hosting_provider")

        # Choose the best available screenshot for reports (seed form > suspicious exploration > early > main).
        screenshot_path = None
        try:
            shots = self.evidence_store.get_all_screenshot_paths(domain)
            screenshot_path = shots[0] if shots else None
        except Exception:
            screenshot_path = None
        if not screenshot_path:
            screenshot_path = self.evidence_store.get_screenshot_path(domain)

        evidence = ReportEvidence(
            domain=hostname,
            url=report_url,
            detected_at=datetime.fromisoformat(
                domain_data.get("first_seen", datetime.now().isoformat())
            ),
            confidence_score=domain_data.get("analysis_score", 0),
            detection_reasons=detection_reasons,
            suspicious_endpoints=suspicious_endpoints,
            screenshot_path=screenshot_path,
            html_path=evidence_dir / "page.html" if evidence_dir else None,
            analysis_path=analysis_path,
            analysis_json=analysis_json,
            backend_domains=backend_domains,
            api_keys_found=api_keys_found,
            hosting_provider=hosting_provider,
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
            if self.enabled_platforms is not None:
                platforms = [p for p in platforms if p in self.enabled_platforms]

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

            # Skip if not configured (should not happen if get_available_platforms is used).
            if not reporter.is_configured():
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.FAILED,
                    message="Reporter not configured",
                )
                continue

            latest = await self.database.get_latest_report(domain_id=domain_id, platform=platform)
            latest_status = (latest.get("status") if latest else "") or ""
            latest_status_lower = str(latest_status).strip().lower()
            next_attempt_at = (latest.get("next_attempt_at") if latest else None)

            # Dedupe: don't re-submit if we already have a successful record.
            if latest_status_lower in {"submitted", "confirmed", "duplicate"}:
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.DUPLICATE,
                    report_id=str(latest.get("id")) if latest else None,
                    message=f"Already reported ({latest_status_lower})",
                )
                continue

            # Manual-required reports shouldn't be re-attempted automatically; keep the last instructions.
            if latest_status_lower == ReportStatus.MANUAL_REQUIRED.value:
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.MANUAL_REQUIRED,
                    report_id=str(latest.get("id")) if latest else None,
                    message=(latest.get("response") if latest else None) or "Manual submission required",
                )
                continue

            # Respect retry schedule for rate-limited reports.
            if latest_status_lower == "rate_limited" and not self._is_timestamp_due(next_attempt_at):
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.RATE_LIMITED,
                    report_id=str(latest.get("id")) if latest else None,
                    message=f"Retry scheduled at {next_attempt_at}",
                )
                continue

            # Check rate limit
            limiter = get_rate_limiter(
                platform,
                reporter.rate_limit_per_minute,
            )

            if not await limiter.acquire(timeout=30):
                retry_after = max(30, int(limiter.wait_time() or 60))
                msg = f"Rate limit exceeded; retry scheduled in {retry_after}s"

                # Create or reuse a report record so the retry worker can pick it up.
                report_row_id = int(latest["id"]) if latest and latest_status_lower in {"rate_limited", "pending", "failed"} else 0
                if not report_row_id:
                    report_row_id = await self.database.add_report(
                        domain_id=domain_id,
                        platform=platform,
                        status=ReportStatus.RATE_LIMITED.value,
                    )
                await self.database.update_report(
                    report_id=report_row_id,
                    status=ReportStatus.RATE_LIMITED.value,
                    response=msg,
                    retry_after=retry_after,
                )

                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.RATE_LIMITED,
                    report_id=str(report_row_id),
                    message=msg,
                    retry_after=retry_after,
                )
                continue

            try:
                # Create or reuse a report row for this platform.
                report_id = int(latest["id"]) if latest and latest_status_lower in {"rate_limited", "pending", "failed"} else 0
                if not report_id:
                    report_id = await self.database.add_report(
                        domain_id=domain_id,
                        platform=platform,
                        status="pending",
                    )

                # Submit report
                result = await reporter.submit(evidence)
                result.report_id = str(report_id)
                results[platform] = result

                if result.status == ReportStatus.MANUAL_REQUIRED:
                    try:
                        content = self._build_manual_instructions_text(platform, evidence, result)
                        await self.evidence_store.save_report_instructions(domain, platform, content)
                    except Exception as e:
                        logger.warning(f"Failed to save manual report instructions for {domain} ({platform}): {e}")

                # Update database
                await self.database.update_report(
                    report_id=report_id,
                    status=result.status.value,
                    response=result.message,
                    retry_after=result.retry_after,
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

        await self._mark_domain_reported_if_needed(domain_id, results)
        return results

    async def _mark_domain_reported_if_needed(
        self, domain_id: int, results: dict[str, ReportResult]
    ) -> None:
        """Update domain status to REPORTED when at least one platform succeeded."""
        from ..storage.database import DomainStatus

        success_statuses = {ReportStatus.SUBMITTED, ReportStatus.CONFIRMED, ReportStatus.DUPLICATE}
        if any(r.status in success_statuses for r in results.values()):
            await self.database.update_domain_status(domain_id, DomainStatus.REPORTED)

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
                ReportStatus.MANUAL_REQUIRED: "📝",
                ReportStatus.FAILED: "❌",
                ReportStatus.RATE_LIMITED: "⏱️",
                ReportStatus.DUPLICATE: "🔄",
                ReportStatus.REJECTED: "🚫",
            }.get(result.status, "❓")

            line = f"  {status_emoji} {platform}: {result.status.value}"
            if result.message:
                msg = result.message.strip()
                # Prefer to show manual URLs/instructions when automation is blocked.
                max_len = 180 if (result.status in {ReportStatus.PENDING, ReportStatus.MANUAL_REQUIRED} or "http" in msg) else 80
                if len(msg) > max_len:
                    msg = msg[: max_len - 1] + "…"
                line += f" - {msg}"
            lines.append(line)

        return "\n".join(lines)
