"""Report manager for coordinating abuse reports across platforms."""

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Optional
from urllib.parse import urlparse

from .base import (
    BaseReporter,
    ConfigurationError,
    ReportEvidence,
    ReportResult,
    ReportStatus,
    ReporterError,
)
from .rate_limiter import get_rate_limiter

if TYPE_CHECKING:
    from ..analyzer.clustering import ThreatCluster, ThreatClusterManager
    from ..storage.database import Database
    from ..storage.evidence import EvidenceStore

logger = logging.getLogger(__name__)


class ReportManager:
    """
    Manages multi-platform abuse reporting.

    Coordinates reporters, handles rate limiting, tracks report status
    in database, and provides evidence packaging.
    """

    # Guardrails for repeated rate limiting to avoid endless churn.
    MAX_RATE_LIMIT_ATTEMPTS: int = 6
    MAX_RATE_LIMIT_BACKOFF_SECONDS: int = 6 * 60 * 60  # 6 hours

    @classmethod
    def _compute_rate_limit_backoff(cls, base_seconds: int, attempts: int) -> int:
        """
        Compute an exponential backoff (capped) for rate-limited retries.

        attempts should be the *next* attempts count after the status update.
        """
        base = max(30, int(base_seconds or 60))
        exponent = min(max(0, int(attempts) - 1), 6)
        return min(base * (2**exponent), cls.MAX_RATE_LIMIT_BACKOFF_SECONDS)

    @staticmethod
    def _preview_only_enabled() -> bool:
        """Return True when reporting should run in preview-only mode."""
        return os.environ.get("REPORT_PREVIEW_ONLY", "false").lower() == "true"

    @staticmethod
    def _dry_run_save_only_enabled() -> bool:
        """Return True when dry-run previews should only be saved locally."""
        return os.environ.get("DRY_RUN_SAVE_ONLY", "false").lower() == "true"

    @staticmethod
    def _ensure_url(target: str) -> str:
        """Ensure a scheme is present so urlparse works predictably."""
        value = (target or "").strip()
        if not value:
            return ""
        if value.startswith(("http://", "https://")):
            return value
        return f"https://{value}"

    @staticmethod
    def _safe_filename_component(value: str) -> str:
        raw = (value or "").strip()
        if not raw:
            return "unknown"
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in raw)[:80]

    @staticmethod
    def _dry_run_email_dir() -> Path:
        data_dir = Path(os.environ.get("DATA_DIR", "./data"))
        return data_dir / "packages" / "dry_run_emails"

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
        if self._preview_only_enabled():
            logger.info("REPORT_PREVIEW_ONLY enabled; skipping retry_due_reports")
            return []

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

                applicable, skip_reason = reporter.is_applicable(evidence)
                if not applicable:
                    msg = skip_reason or "Not applicable"
                    result = ReportResult(
                        platform=platform,
                        status=ReportStatus.SKIPPED,
                        report_id=str(report_id),
                        message=msg,
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
                    current_attempts = int(row.get("attempts") or 0)
                    next_attempts = current_attempts + 1
                    base_retry_after = max(30, int(limiter.wait_time() or 60))

                    if next_attempts > self.MAX_RATE_LIMIT_ATTEMPTS:
                        platform_url = (getattr(reporter, "platform_url", "") or "").strip()
                        url_line = f"\n\nManual URL: {platform_url}" if platform_url else ""
                        msg = (
                            f"Rate limit persisted after {current_attempts} attempts; pausing retries.{url_line}\n\n"
                            f"URL: {evidence.url}"
                        )
                        result = ReportResult(
                            platform=platform,
                            status=ReportStatus.MANUAL_REQUIRED,
                            report_id=str(report_id),
                            message=msg,
                            response_data={"domain_id": domain_id, "domain": domain},
                        )
                        attempted.append(result)
                        try:
                            content = self._build_manual_instructions_text(platform, evidence, result)
                            await self.evidence_store.save_report_instructions(domain, platform, content)
                        except Exception as e:
                            logger.warning(f"Failed to save manual report instructions for {domain} ({platform}): {e}")
                        await self.database.update_report(
                            report_id=report_id,
                            status=result.status.value,
                            response=result.message,
                        )
                        continue

                    retry_after = self._compute_rate_limit_backoff(base_retry_after, next_attempts)
                    msg = (
                        f"Rate limit exceeded; retry scheduled in {retry_after}s "
                        f"(attempt {next_attempts}/{self.MAX_RATE_LIMIT_ATTEMPTS})"
                    )
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
                if result.status == ReportStatus.RATE_LIMITED:
                    current_attempts = int(row.get("attempts") or 0)
                    next_attempts = current_attempts + 1
                    base_retry_after = int(result.retry_after or 60)

                    if next_attempts > self.MAX_RATE_LIMIT_ATTEMPTS:
                        platform_url = (getattr(reporter, "platform_url", "") or "").strip()
                        url_line = f"\n\nManual URL: {platform_url}" if platform_url else ""
                        msg = (
                            f"Rate limited by platform after {current_attempts} attempts; pausing retries.{url_line}\n\n"
                            f"URL: {evidence.url}"
                        )
                        result = ReportResult(
                            platform=platform,
                            status=ReportStatus.MANUAL_REQUIRED,
                            report_id=str(report_id),
                            message=msg,
                            response_data={"domain_id": domain_id, "domain": domain},
                        )
                    else:
                        retry_after = self._compute_rate_limit_backoff(base_retry_after, next_attempts)
                        result.retry_after = retry_after
                        base_msg = (result.message or "Rate limited").strip()
                        result.message = (
                            f"{base_msg}; retry scheduled in {retry_after}s "
                            f"(attempt {next_attempts}/{self.MAX_RATE_LIMIT_ATTEMPTS})"
                        )

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
        from .registrar import RegistrarReporter
        from .apwg import APWGReporter
        from .microsoft import MicrosoftReporter
        from .resend_reporter import ResendReporter
        from .digitalocean import DigitalOceanReporter

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

        # APWG manual helper (opt-in via REPORT_PLATFORMS)
        self.reporters["apwg"] = APWGReporter()
        logger.info("Initialized APWG manual reporter")

        # Microsoft manual helper (opt-in via REPORT_PLATFORMS)
        self.reporters["microsoft"] = MicrosoftReporter()
        logger.info("Initialized Microsoft manual reporter")

        # Hosting provider manual helper (opt-in via REPORT_PLATFORMS)
        self.reporters["hosting_provider"] = HostingProviderReporter(
            reporter_email=self.resend_from_email or self.reporter_email or ""
        )
        logger.info("Initialized hosting provider manual reporter")

        # Registrar manual helper (opt-in via REPORT_PLATFORMS)
        self.reporters["registrar"] = RegistrarReporter(
            reporter_email=self.resend_from_email or self.reporter_email or ""
        )
        logger.info("Initialized registrar manual reporter")

        # Resend email reporter (configured when API key is present)
        self.reporters["resend"] = ResendReporter(
            api_key=self.resend_api_key or "",
            from_email=self.resend_from_email or self.reporter_email or "SeedBuster <onboarding@resend.dev>",
        )
        if self.resend_api_key:
            logger.info(f"Initialized Resend email reporter (from: {self.resend_from_email or self.reporter_email})")
        else:
            logger.info("Resend email reporter not configured (missing RESEND_API_KEY)")

        # DigitalOcean form reporter (configured when reporter email is present)
        reporter_email = self.resend_from_email or self.reporter_email or ""
        self.reporters["digitalocean"] = DigitalOceanReporter(
            reporter_email=reporter_email.split("<")[-1].rstrip(">") if "<" in reporter_email else reporter_email,
            reporter_name="Kaspa Security",
        )
        if reporter_email:
            logger.info("Initialized DigitalOcean form reporter (Playwright)")
        else:
            logger.info("DigitalOcean form reporter not configured (missing reporter email)")

        # SMTP reporter (configured when SMTP host and from_email are present)
        self.reporters["smtp"] = SMTPReporter(
            host=self.smtp_config.get("host", ""),
            port=self.smtp_config.get("port", 587),
            username=self.smtp_config.get("username", ""),
            password=self.smtp_config.get("password", ""),
            from_email=self.smtp_config.get("from_email", self.reporter_email),
        )
        if self.smtp_config.get("host"):
            logger.info("Initialized SMTP reporter")
        else:
            logger.info("SMTP reporter not configured (missing SMTP_HOST)")

        # Warn if enabled_platforms includes unknown/uninitialized reporters.
        if self.enabled_platforms is not None:
            unknown = sorted(p for p in self.enabled_platforms if p not in self.reporters)
            if unknown:
                logger.warning(f"Unknown report platforms in REPORT_PLATFORMS: {', '.join(unknown)}")

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
        *,
        force: bool = False,
        dry_run: bool = False,
        dry_run_email: Optional[str] = None,
    ) -> dict[str, ReportResult]:
        """
        Submit reports to multiple platforms.

        Args:
            domain_id: Database ID of the domain
            domain: Domain name
            platforms: List of platforms to report to (None = all configured)
            force: When True, bypass rate-limited schedules and attempt submission immediately
            dry_run: When True, send reports to dry_run_email instead of real platforms
            dry_run_email: Email address to receive dry-run reports

        Returns:
            Dict mapping platform name to ReportResult
        """
        if self._preview_only_enabled():
            dry_run = True
            if dry_run_email is None:
                dry_run_email = os.environ.get("DRY_RUN_EMAIL", "")

        # Handle dry-run mode
        if dry_run:
            return await self._dry_run_domain_report(
                domain_id=domain_id,
                domain=domain,
                platforms=platforms,
                dry_run_email=dry_run_email or os.environ.get("DRY_RUN_EMAIL", ""),
            )
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

            # Respect retry schedule for rate-limited reports unless explicitly forced.
            if not force and latest_status_lower == "rate_limited" and not self._is_timestamp_due(next_attempt_at):
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.RATE_LIMITED,
                    report_id=str(latest.get("id")) if latest else None,
                    message=f"Retry scheduled at {next_attempt_at}",
                )
                continue

            applicable, skip_reason = reporter.is_applicable(evidence)
            if not applicable:
                msg = skip_reason or "Not applicable"
                report_row_id = int(latest["id"]) if latest and latest_status_lower in {"rate_limited", "pending", "failed", "skipped"} else 0
                if not report_row_id:
                    report_row_id = await self.database.add_report(
                        domain_id=domain_id,
                        platform=platform,
                        status=ReportStatus.SKIPPED.value,
                    )
                await self.database.update_report(
                    report_id=report_row_id,
                    status=ReportStatus.SKIPPED.value,
                    response=msg,
                )
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SKIPPED,
                    report_id=str(report_row_id),
                    message=msg,
                )
                continue

            # Check rate limit
            limiter = get_rate_limiter(
                platform,
                reporter.rate_limit_per_minute,
            )

            if not await limiter.acquire(timeout=30):
                base_retry_after = max(30, int(limiter.wait_time() or 60))

                # Create or reuse a report record so the retry worker can pick it up.
                report_row_id = int(latest["id"]) if latest and latest_status_lower in {"rate_limited", "pending", "failed", "skipped"} else 0
                current_attempts = int(latest.get("attempts") or 0) if report_row_id and latest and int(latest["id"]) == report_row_id else 0
                if not report_row_id:
                    report_row_id = await self.database.add_report(
                        domain_id=domain_id,
                        platform=platform,
                        status=ReportStatus.RATE_LIMITED.value,
                    )
                    current_attempts = 0

                next_attempts = current_attempts + 1
                if next_attempts > self.MAX_RATE_LIMIT_ATTEMPTS:
                    platform_url = (getattr(reporter, "platform_url", "") or "").strip()
                    url_line = f"\n\nManual URL: {platform_url}" if platform_url else ""
                    msg = (
                        f"Rate limit persisted after {current_attempts} attempts; pausing retries.{url_line}\n\n"
                        f"URL: {evidence.url}"
                    )
                    result = ReportResult(
                        platform=platform,
                        status=ReportStatus.MANUAL_REQUIRED,
                        report_id=str(report_row_id),
                        message=msg,
                    )
                    results[platform] = result
                    try:
                        content = self._build_manual_instructions_text(platform, evidence, result)
                        await self.evidence_store.save_report_instructions(domain, platform, content)
                    except Exception as e:
                        logger.warning(f"Failed to save manual report instructions for {domain} ({platform}): {e}")
                    await self.database.update_report(
                        report_id=report_row_id,
                        status=result.status.value,
                        response=result.message,
                    )
                    continue

                retry_after = self._compute_rate_limit_backoff(base_retry_after, next_attempts)
                msg = (
                    f"Rate limit exceeded; retry scheduled in {retry_after}s "
                    f"(attempt {next_attempts}/{self.MAX_RATE_LIMIT_ATTEMPTS})"
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
                report_id = int(latest["id"]) if latest and latest_status_lower in {"rate_limited", "pending", "failed", "skipped"} else 0
                if not report_id:
                    report_id = await self.database.add_report(
                        domain_id=domain_id,
                        platform=platform,
                        status="pending",
                    )
                    current_attempts = 0
                else:
                    current_attempts = int(latest.get("attempts") or 0) if latest and int(latest["id"]) == report_id else 0

                # Submit report
                result = await reporter.submit(evidence)

                if result.status == ReportStatus.RATE_LIMITED:
                    next_attempts = current_attempts + 1
                    base_retry_after = int(result.retry_after or 60)
                    if next_attempts > self.MAX_RATE_LIMIT_ATTEMPTS:
                        platform_url = (getattr(reporter, "platform_url", "") or "").strip()
                        url_line = f"\n\nManual URL: {platform_url}" if platform_url else ""
                        msg = (
                            f"Rate limited by platform after {current_attempts} attempts; pausing retries.{url_line}\n\n"
                            f"URL: {evidence.url}"
                        )
                        result = ReportResult(
                            platform=platform,
                            status=ReportStatus.MANUAL_REQUIRED,
                            message=msg,
                        )
                    else:
                        retry_after = self._compute_rate_limit_backoff(base_retry_after, next_attempts)
                        result.retry_after = retry_after
                        base_msg = (result.message or "Rate limited").strip()
                        result.message = (
                            f"{base_msg}; retry scheduled in {retry_after}s "
                            f"(attempt {next_attempts}/{self.MAX_RATE_LIMIT_ATTEMPTS})"
                        )

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

    async def mark_manual_done(
        self,
        domain_id: int,
        domain: str,
        platforms: Optional[list[str]] = None,
        *,
        note: str = "Manual submission marked complete",
    ) -> dict[str, ReportResult]:
        """
        Mark MANUAL_REQUIRED reports as completed (SUBMITTED).

        This is used after an operator submits reports manually so they don't linger
        in the manual queue indefinitely.
        """
        # Determine platforms present for this domain if none were provided.
        target_platforms: list[str] = []
        if platforms is None:
            rows = await self.database.get_reports_for_domain(domain_id)
            seen: set[str] = set()
            for row in rows:
                p = str(row.get("platform") or "").strip().lower()
                if not p or p in seen:
                    continue
                seen.add(p)
                target_platforms.append(p)
        else:
            seen: set[str] = set()
            for p in platforms:
                value = str(p or "").strip().lower()
                if not value or value in seen:
                    continue
                seen.add(value)
                target_platforms.append(value)

        if not target_platforms:
            return {
                "error": ReportResult(
                    platform="manager",
                    status=ReportStatus.FAILED,
                    message="No platforms found for this domain",
                )
            }

        results: dict[str, ReportResult] = {}
        marker = f"{note} at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC (SeedBuster operator)"

        for platform in target_platforms:
            latest = await self.database.get_latest_report(domain_id=domain_id, platform=platform)
            if not latest:
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SKIPPED,
                    message="No report record found",
                )
                continue

            report_id = int(latest["id"])
            latest_status_lower = str(latest.get("status") or "").strip().lower()
            if latest_status_lower != ReportStatus.MANUAL_REQUIRED.value:
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SKIPPED,
                    report_id=str(report_id),
                    message=f"No manual action needed (status: {latest_status_lower or 'unknown'})",
                )
                continue

            prev_response = str(latest.get("response") or "")
            response = prev_response
            if marker not in prev_response:
                response = (prev_response.rstrip() + "\n\n" + marker).strip() if prev_response.strip() else marker

            await self.database.update_report(
                report_id=report_id,
                status=ReportStatus.SUBMITTED.value,
                response=response,
            )
            results[platform] = ReportResult(
                platform=platform,
                status=ReportStatus.SUBMITTED,
                report_id=str(report_id),
                message="Marked as manually submitted",
            )

        await self._mark_domain_reported_if_needed(domain_id, results)
        return results

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
                ReportStatus.SKIPPED: "➖",
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

    # -------------------------------------------------------------------------
    # Dry-Run Mode - Preview reports before sending
    # -------------------------------------------------------------------------

    async def _dry_run_domain_report(
        self,
        domain_id: int,
        domain: str,
        platforms: Optional[list[str]] = None,
        dry_run_email: str = "",
    ) -> dict[str, ReportResult]:
        """
        Send dry-run preview of reports to specified email instead of real platforms.

        Each platform's report is sent as a separate email so you can see exactly
        what each abuse team would receive.
        """
        if not dry_run_email and not self._dry_run_save_only_enabled():
            return {
                "error": ReportResult(
                    platform="dry_run",
                    status=ReportStatus.FAILED,
                    message="No dry-run email configured. Set DRY_RUN_EMAIL or pass dry_run_email parameter.",
                )
            }

        # Build evidence
        evidence = await self.build_evidence(domain_id, domain)
        if not evidence:
            return {
                "error": ReportResult(
                    platform="dry_run",
                    status=ReportStatus.FAILED,
                    message=f"Could not build evidence for domain {domain}",
                )
            }

        # Determine platforms
        if platforms is None:
            platforms = self.get_available_platforms()
        else:
            platforms = [p for p in platforms if p in self.reporters]
            if self.enabled_platforms is not None:
                platforms = [p for p in platforms if p in self.enabled_platforms]

        results: dict[str, ReportResult] = {}

        for platform in platforms:
            reporter = self.reporters.get(platform)
            if not reporter or not reporter.is_configured():
                continue

            applicable, skip_reason = reporter.is_applicable(evidence)
            if not applicable:
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SKIPPED,
                    message=skip_reason or "Not applicable",
                )
                continue

            # Build the report content that would be sent
            try:
                report_content = self._build_platform_report_preview(platform, evidence)
                saved = await self._send_dry_run_email(
                    to_email=dry_run_email,
                    platform=platform,
                    domain=domain,
                    report_content=report_content,
                    evidence=evidence,
                )
                if self._dry_run_save_only_enabled():
                    msg = f"Dry-run saved: {saved}"
                else:
                    msg = f"Dry-run sent to {dry_run_email}"
                    if saved:
                        msg += f" (saved: {saved})"
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.SUBMITTED,
                    message=msg,
                )
            except Exception as e:
                logger.error(f"Failed to send dry-run for {platform}: {e}")
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.FAILED,
                    message=f"Dry-run failed: {e}",
                )

        return results

    def _build_platform_report_preview(self, platform: str, evidence: ReportEvidence) -> str:
        """Build preview of what would be sent to a platform."""
        from .templates import ReportTemplates

        reporter_email = (self.resend_from_email or self.reporter_email or "").strip()
        reporter_email_addr = reporter_email
        if "<" in reporter_email_addr and ">" in reporter_email_addr:
            reporter_email_addr = reporter_email_addr.split("<")[-1].rstrip(">").strip()

        # Get the template content for this platform
        if platform == "digitalocean":
            # Mirror the payload built by DigitalOceanReporter (Playwright form).
            all_domains = (evidence.backend_domains or []) + (evidence.suspicious_endpoints or [])
            do_apps: list[str] = []
            for d in all_domains:
                if not isinstance(d, str):
                    continue
                if "ondigitalocean.app" not in d.lower():
                    continue
                if "://" in d:
                    parsed = urlparse(d)
                    if parsed.netloc:
                        do_apps.append(parsed.netloc)
                else:
                    do_apps.append(d)
            do_apps = sorted(set(do_apps))

            seed_hint = ReportTemplates._extract_seed_phrase_indicator(evidence.detection_reasons)
            seed_line = (
                f"Requests seed phrase ('{seed_hint}')"
                if seed_hint
                else "Requests cryptocurrency seed phrase"
            )
            highlights = ReportTemplates._summarize_reasons(evidence.detection_reasons, max_items=4)

            description = f"""CRYPTOCURRENCY PHISHING - Apps to suspend:
{chr(10).join(f'- {app}' for app in do_apps)}

Phishing URL: {evidence.url}
Observed: {seed_line}
Confidence: {evidence.confidence_score}%

Key evidence (automated capture):
{chr(10).join(f'- {r}' for r in highlights)}

Captured evidence (screenshot + HTML) available on request.

Detected by SeedBuster - github.com/elldeeone/seedbuster"""

            return f"""
DIGITALOCEAN ABUSE REPORT PREVIEW
=================================

Form URL: https://www.digitalocean.com/company/contact/abuse#phishing

Field: name
Value: Kaspa Security

Field: email
Value: {reporter_email_addr or "(not set)"}

Field: target
Value: Kaspa cryptocurrency wallet users

Field: evidence_url
Value: {evidence.url}

Field: description
Value:
{description}
"""
        elif platform == "cloudflare":
            template_data = ReportTemplates.cloudflare(evidence, reporter_email_addr or "")
            return f"""
CLOUDFLARE ABUSE REPORT PREVIEW
===============================

Form URL: https://abuse.cloudflare.com/phishing

Field: urls
Value: {evidence.url}

Field: abuse_type
Value: phishing

Field: comments
Value:
{template_data.get('body', 'N/A')}

Field: email (optional)
Value: {reporter_email_addr or "(not set)"}

Field: name
Value: SeedBuster
"""
        elif platform == "google":
            additional_info = ReportTemplates.google_safebrowsing_comment(evidence)
            return f"""
GOOGLE SAFE BROWSING REPORT PREVIEW
===================================

Form URL: https://safebrowsing.google.com/safebrowsing/report_phish/

Field: url
Value: {evidence.url}

Field: dq (additional details)
Value:
{additional_info}

Note: Google's form includes dynamic hidden fields; SeedBuster auto-discovers them at submit time.
"""
        elif platform == "netcraft":
            seed_hint = ReportTemplates._extract_seed_phrase_indicator(evidence.detection_reasons)
            seed_line = (
                f"Requests seed phrase ('{seed_hint}')."
                if seed_hint
                else "Requests cryptocurrency seed phrase."
            )
            highlights = ReportTemplates._summarize_reasons(evidence.detection_reasons, max_items=4)

            reason_lines = [
                "Cryptocurrency phishing (seed phrase theft).",
                seed_line,
                f"Confidence: {evidence.confidence_score}%",
                "",
                "Key evidence (automated capture):",
                *[f"- {r}" for r in highlights],
                "",
                "Captured evidence (screenshot + HTML) available on request.",
                "",
                "Detected by SeedBuster.",
            ]
            reason = "\n".join(reason_lines).strip()

            payload: dict[str, object] = {
                "urls": [
                    {
                        "url": evidence.url,
                        "reason": reason,
                    }
                ]
            }
            if reporter_email_addr:
                payload["email"] = reporter_email_addr

            return f"""
NETCRAFT REPORT PREVIEW
======================

Endpoint: https://report.netcraft.com/api/v3/report/urls
Method: POST
Body (JSON):
{json.dumps(payload, indent=2)}
"""
        elif platform in ("registrar", "resend", "smtp"):
            template_data = ReportTemplates.generic_email(evidence, reporter_email or reporter_email_addr or "")
            return f"""
EMAIL REPORT PREVIEW
====================

Would send to: [Registrar abuse contact via RDAP lookup]

Subject: {template_data.get('subject', 'N/A')}

Body:
{template_data.get('body', 'N/A')}
"""
        else:
            return f"""
{platform.upper()} REPORT PREVIEW
{'=' * (len(platform) + 16)}

Platform: {platform}
Domain: {evidence.domain}
URL: {evidence.url}
Confidence: {evidence.confidence_score}%

Evidence Summary:
{evidence.to_summary()}
"""

    async def _send_dry_run_email(
        self,
        to_email: str,
        platform: str,
        domain: str,
        report_content: str,
        evidence: ReportEvidence,
    ) -> Path:
        """Send a dry-run preview email."""
        attachments: list[Path] = []
        if evidence.screenshot_path and evidence.screenshot_path.exists():
            attachments.append(evidence.screenshot_path)
        if evidence.html_path and evidence.html_path.exists():
            attachments.append(evidence.html_path)

        subject = f"[DRY-RUN] Platform: {platform} | Domain: {domain}"
        body = f"""
This is a DRY-RUN preview of what would be submitted to {platform}.

{'=' * 60}
REPORT PREVIEW
{'=' * 60}

{report_content}

{'=' * 60}
EVIDENCE SUMMARY
{'=' * 60}

Domain: {evidence.domain}
URL: {evidence.url}
Confidence: {evidence.confidence_score}%
Detection Time: {evidence.detected_at.isoformat()}

Detection Reasons:
{chr(10).join(f'  - {r}' for r in evidence.detection_reasons)}

Backend Infrastructure:
{chr(10).join(f'  - {b}' for b in evidence.backend_domains) if evidence.backend_domains else '  (none detected)'}

{'=' * 60}
This email was generated by SeedBuster dry-run mode.
To submit for real, run the command without --dry-run.
"""

        out_dir = self._dry_run_email_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        safe_platform = self._safe_filename_component(platform)
        safe_domain = self._safe_filename_component(domain)
        base = out_dir / f"{ts}_{safe_platform}_{safe_domain}"
        txt_path = base.with_suffix(".txt")
        meta_path = base.with_suffix(".json")

        try:
            txt_path.write_text(
                f"To: {to_email}\nSubject: {subject}\n\n{body.lstrip()}",
                encoding="utf-8",
            )
            meta_path.write_text(
                json.dumps(
                    {
                        "saved_at": ts,
                        "to_email": to_email,
                        "subject": subject,
                        "platform": platform,
                        "domain": domain,
                        "evidence_domain": evidence.domain,
                        "url": evidence.url,
                        "attachments": [str(p) for p in attachments],
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        except Exception as e:  # pragma: no cover - best-effort only
            logger.warning("Failed to save dry-run preview: %s", e)

        if self._dry_run_save_only_enabled():
            logger.info("DRY_RUN_SAVE_ONLY enabled; skipping sending preview email (%s)", txt_path)
            return txt_path

        resend_reporter = self.reporters.get("resend")
        if resend_reporter and resend_reporter.is_configured():
            try:
                send_email = getattr(resend_reporter, "send_email", None)
                if callable(send_email):
                    await send_email(to_email=to_email, subject=subject, body=body, attachments=attachments)
                    return txt_path
            except Exception as e:
                raise ReporterError(f"Resend dry-run email failed: {e} (saved: {txt_path})") from e

        smtp_reporter = self.reporters.get("smtp")
        if smtp_reporter and smtp_reporter.is_configured():
            try:
                ok = await smtp_reporter.send_email(
                    to_email=to_email,
                    subject=subject,
                    body=body,
                    attachments=attachments,
                )
                if not ok:
                    raise ReporterError("SMTP dry-run email failed")
                return txt_path
            except Exception as e:
                raise ReporterError(f"SMTP dry-run email failed: {e} (saved: {txt_path})") from e

        raise ConfigurationError(
            "No email service configured for dry-run previews. "
            "Configure RESEND_API_KEY or SMTP settings."
            f" (saved: {txt_path})"
        )

    # -------------------------------------------------------------------------
    # Campaign Reporting - Report entire clusters in parallel
    # -------------------------------------------------------------------------

    async def report_campaign(
        self,
        cluster_id: str,
        cluster_manager: "ThreatClusterManager",
        platforms: Optional[list[str]] = None,
        *,
        dry_run: bool = False,
        dry_run_email: Optional[str] = None,
        generate_evidence_package: bool = True,
    ) -> dict[str, list[ReportResult]]:
        """
        Report an entire campaign/cluster in parallel to all relevant targets.

        Args:
            cluster_id: ID of the cluster to report
            cluster_manager: ThreatClusterManager instance
            platforms: Specific platforms to report to (None = all)
            dry_run: Send previews to dry_run_email instead of real targets
            dry_run_email: Email for dry-run previews
            generate_evidence_package: Whether to generate PDF/evidence archives

        Returns:
            Dict mapping target type to list of results:
            - "backends": Results from backend provider reports (DO, Vercel)
            - "registrars": Results from registrar reports
            - "blocklists": Results from blocklist submissions
            - "frontends": Results from individual domain reports
        """
        if self._preview_only_enabled():
            dry_run = True
            if dry_run_email is None:
                dry_run_email = os.environ.get("DRY_RUN_EMAIL", "")

        cluster = cluster_manager.clusters.get(cluster_id)
        if not cluster:
            return {
                "error": [ReportResult(
                    platform="campaign",
                    status=ReportStatus.FAILED,
                    message=f"Cluster not found: {cluster_id}",
                )]
            }

        results: dict[str, list[ReportResult]] = {
            "backends": [],
            "registrars": [],
            "blocklists": [],
            "frontends": [],
        }

        dry_run_email = dry_run_email or os.environ.get("DRY_RUN_EMAIL", "")

        # Generate evidence package if requested
        if generate_evidence_package:
            try:
                from .evidence_packager import EvidencePackager
                packager = EvidencePackager(
                    database=self.database,
                    evidence_store=self.evidence_store,
                    cluster_manager=cluster_manager,
                )
                if dry_run:
                    # Just generate the reports, don't archive
                    from .report_generator import ReportGenerator
                    generator = ReportGenerator(
                        database=self.database,
                        evidence_store=self.evidence_store,
                        cluster_manager=cluster_manager,
                    )
                    html_path = await generator.generate_campaign_html(cluster_id)
                    logger.info(f"Generated campaign report: {html_path}")
                else:
                    archive_path = await packager.create_campaign_archive(cluster_id)
                    logger.info(f"Generated campaign archive: {archive_path}")
            except Exception as e:
                logger.error(f"Failed to generate evidence package: {e}")

        # 1. Report to backend providers (highest priority)
        backend_tasks = []
        for backend in cluster.shared_backends:
            if "digitalocean" in backend.lower():
                backend_tasks.append(
                    self._report_backend(
                        backend=backend,
                        cluster=cluster,
                        platform="digitalocean",
                        dry_run=dry_run,
                        dry_run_email=dry_run_email,
                    )
                )
            elif "vercel" in backend.lower():
                # TODO: Add Vercel reporter
                logger.info(f"Vercel backend detected but no reporter implemented: {backend}")

        if backend_tasks:
            backend_results = await asyncio.gather(*backend_tasks, return_exceptions=True)
            for result in backend_results:
                if isinstance(result, Exception):
                    results["backends"].append(ReportResult(
                        platform="backend",
                        status=ReportStatus.FAILED,
                        message=str(result),
                    ))
                else:
                    results["backends"].append(result)

        # 2. Report to blocklists (parallel)
        blocklist_platforms = ["google", "netcraft", "phishtank"]
        if platforms:
            blocklist_platforms = [p for p in blocklist_platforms if p in platforms]

        for member in cluster.members:
            domain_data = await self.database.get_domain(member.domain)
            if not domain_data:
                continue

            domain_id = domain_data.get("id")
            if not domain_id:
                continue

            blocklist_results = await self.report_domain(
                domain_id=domain_id,
                domain=member.domain,
                platforms=blocklist_platforms,
                dry_run=dry_run,
                dry_run_email=dry_run_email,
            )
            for platform, result in blocklist_results.items():
                results["blocklists"].append(result)

        # 3. Report to registrars (grouped by registrar)
        # TODO: Group domains by registrar and send bulk reports

        # 4. Report individual frontends (if not already done via blocklists)
        frontend_platforms = [p for p in (platforms or self.get_available_platforms())
                             if p not in blocklist_platforms]

        for member in cluster.members:
            domain_data = await self.database.get_domain(member.domain)
            if not domain_data:
                continue

            domain_id = domain_data.get("id")
            if not domain_id:
                continue

            frontend_results = await self.report_domain(
                domain_id=domain_id,
                domain=member.domain,
                platforms=frontend_platforms,
                dry_run=dry_run,
                dry_run_email=dry_run_email,
            )
            for platform, result in frontend_results.items():
                results["frontends"].append(result)

        return results

    async def _report_backend(
        self,
        backend: str,
        cluster: "ThreatCluster",
        platform: str,
        dry_run: bool = False,
        dry_run_email: str = "",
    ) -> ReportResult:
        """Report a backend server with campaign context."""
        reporter = self.reporters.get(platform)
        if not reporter or not reporter.is_configured():
            return ReportResult(
                platform=platform,
                status=ReportStatus.FAILED,
                message=f"Reporter not configured: {platform}",
            )

        # Build evidence for the backend report
        # Use the first domain in the cluster as the primary evidence
        if not cluster.members:
            return ReportResult(
                platform=platform,
                status=ReportStatus.FAILED,
                message="No domains in cluster",
            )

        primary_domain = cluster.members[0].domain
        domain_data = await self.database.get_domain(primary_domain)
        if not domain_data:
            return ReportResult(
                platform=platform,
                status=ReportStatus.FAILED,
                message=f"Domain not found: {primary_domain}",
            )

        evidence = await self.build_evidence(
            domain_id=domain_data.get("id"),
            domain=primary_domain,
        )
        if not evidence:
            return ReportResult(
                platform=platform,
                status=ReportStatus.FAILED,
                message="Could not build evidence",
            )

        # Enhance evidence with campaign context
        evidence.backend_domains = list(cluster.shared_backends)

        if dry_run:
            report_content = self._build_platform_report_preview(platform, evidence)
            report_content = f"""
CAMPAIGN CONTEXT
================
This backend is part of campaign: {cluster.name}
Total domains using this backend: {len(cluster.members)}
Domains: {', '.join(m.domain for m in cluster.members[:10])}{'...' if len(cluster.members) > 10 else ''}

{report_content}
"""
            saved = await self._send_dry_run_email(
                to_email=dry_run_email,
                platform=f"{platform}_backend",
                domain=backend,
                report_content=report_content,
                evidence=evidence,
            )
            if self._dry_run_save_only_enabled():
                msg = f"Dry-run saved: {saved}"
            else:
                msg = f"Dry-run sent to {dry_run_email}"
                if saved:
                    msg += f" (saved: {saved})"
            return ReportResult(
                platform=f"{platform}_backend",
                status=ReportStatus.SUBMITTED,
                message=msg,
            )

        # Submit real report
        result = await reporter.submit(evidence)
        result.platform = f"{platform}_backend"
        return result
