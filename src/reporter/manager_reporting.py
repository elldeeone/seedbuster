"""Report submission helpers for ReportManager."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import TYPE_CHECKING, Optional

from .base import ReportResult, ReportStatus, ReporterError

if TYPE_CHECKING:
    from ..analyzer.campaigns import ThreatCampaign, ThreatCampaignManager

logger = logging.getLogger(__name__)


class ReportManagerReportingMixin:
    """Report submission helpers."""

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

        # Handle dry-run mode.
        if dry_run:
            return await self._dry_run_domain_report(
                domain_id=domain_id,
                domain=domain,
                platforms=platforms,
                dry_run_email=dry_run_email or os.environ.get("DRY_RUN_EMAIL", ""),
            )

        # Build evidence package.
        evidence = await self.build_evidence(domain_id, domain)
        if not evidence:
            return {
                "error": ReportResult(
                    platform="manager",
                    status=ReportStatus.FAILED,
                    message=f"Could not build evidence for domain {domain}",
                )
            }

        # Determine platforms to report to.
        if platforms is None:
            platforms = self.get_available_platforms()
        else:
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

        results: dict[str, ReportResult] = {}

        for platform in platforms:
            reporter = self.reporters[platform]

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

            # Manual-required reports shouldn't be re-attempted automatically.
            if latest_status_lower == ReportStatus.MANUAL_REQUIRED.value:
                response_data = None
                if latest:
                    raw_response_data = latest.get("response_data")
                    if raw_response_data:
                        try:
                            response_data = (
                                json.loads(raw_response_data)
                                if isinstance(raw_response_data, str)
                                else raw_response_data
                            )
                        except (json.JSONDecodeError, TypeError):
                            pass
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.MANUAL_REQUIRED,
                    report_id=str(latest.get("id")) if latest else None,
                    message=(latest.get("response") if latest else None)
                    or "Manual submission required",
                    response_data=response_data,
                )
                continue

            # Respect retry schedule for rate-limited reports unless explicitly forced.
            if (
                not force
                and latest_status_lower == "rate_limited"
                and not self._is_timestamp_due(next_attempt_at)
            ):
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
                report_row_id = (
                    int(latest["id"])
                    if latest and latest_status_lower in {"rate_limited", "pending", "failed", "skipped"}
                    else 0
                )
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

            limiter = self._get_rate_limiter(platform, reporter.rate_limit_per_minute)

            if not await limiter.acquire(timeout=30):
                base_retry_after = max(30, int(limiter.wait_time() or 60))

                report_row_id = (
                    int(latest["id"])
                    if latest and latest_status_lower in {"rate_limited", "pending", "failed", "skipped"}
                    else 0
                )
                current_attempts = (
                    int(latest.get("attempts") or 0)
                    if report_row_id and latest and int(latest["id"]) == report_row_id
                    else 0
                )
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
                    except Exception as exc:
                        logger.warning(
                            "Failed to save manual report instructions for %s (%s): %s",
                            domain,
                            platform,
                            exc,
                        )
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
                report_id = (
                    int(latest["id"])
                    if latest and latest_status_lower in {"rate_limited", "pending", "failed", "skipped"}
                    else 0
                )
                if not report_id:
                    report_id = await self.database.add_report(
                        domain_id=domain_id,
                        platform=platform,
                        status="pending",
                    )
                    current_attempts = 0
                else:
                    current_attempts = (
                        int(latest.get("attempts") or 0)
                        if latest and int(latest["id"]) == report_id
                        else 0
                    )

                result = await reporter.submit(evidence)

                if result.status == ReportStatus.RATE_LIMITED:
                    next_attempts = current_attempts + 1
                    base_retry_after = int(result.retry_after or 60)
                    if next_attempts > self.MAX_RATE_LIMIT_ATTEMPTS:
                        platform_url = (getattr(reporter, "platform_url", "") or "").strip()
                        url_line = f"\n\nManual URL: {platform_url}" if platform_url else ""
                        msg = (
                            f"Rate limited by platform after {current_attempts} attempts; "
                            f"pausing retries.{url_line}\n\n"
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
                    except Exception as exc:
                        logger.warning(
                            "Failed to save manual report instructions for %s (%s): %s",
                            domain,
                            platform,
                            exc,
                        )

                response_data_json = None
                if result.response_data:
                    try:
                        response_data_json = json.dumps(result.response_data)
                    except Exception:
                        pass

                await self.database.update_report(
                    report_id=report_id,
                    status=result.status.value,
                    response=result.message,
                    response_data=response_data_json,
                    retry_after=result.retry_after,
                )

                logger.info("Report submitted to %s: %s", platform, result.status.value)

            except ReporterError as exc:
                logger.error("Reporter error for %s: %s", platform, exc)
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.FAILED,
                    message=str(exc),
                )

            except Exception as exc:
                logger.exception("Unexpected error reporting to %s", platform)
                results[platform] = ReportResult(
                    platform=platform,
                    status=ReportStatus.FAILED,
                    message=f"Unexpected error: {exc}",
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

    async def report_campaign(
        self,
        campaign_id: str,
        campaign_manager: "ThreatCampaignManager",
        platforms: Optional[list[str]] = None,
        *,
        dry_run: bool = False,
        dry_run_email: Optional[str] = None,
        generate_evidence_package: bool = True,
    ) -> dict[str, list[ReportResult]]:
        """
        Report an entire campaign in parallel to all relevant targets.

        Args:
            campaign_id: ID of the campaign to report
            campaign_manager: ThreatCampaignManager instance
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

        campaign = campaign_manager.campaigns.get(campaign_id)
        if not campaign:
            return {
                "error": [
                    ReportResult(
                        platform="campaign",
                        status=ReportStatus.FAILED,
                        message=f"Campaign not found: {campaign_id}",
                    )
                ]
            }

        results: dict[str, list[ReportResult]] = {
            "backends": [],
            "registrars": [],
            "blocklists": [],
            "frontends": [],
        }

        dry_run_email = dry_run_email or os.environ.get("DRY_RUN_EMAIL", "")

        if generate_evidence_package:
            try:
                from .evidence_packager import EvidencePackager

                packager = EvidencePackager(
                    database=self.database,
                    evidence_store=self.evidence_store,
                    campaign_manager=campaign_manager,
                )
                if dry_run:
                    from .report_generator import ReportGenerator

                    generator = ReportGenerator(
                        database=self.database,
                        evidence_store=self.evidence_store,
                        campaign_manager=campaign_manager,
                    )
                    html_path = await generator.generate_campaign_html(campaign_id)
                    logger.info("Generated campaign report: %s", html_path)
                else:
                    archive_path = await packager.create_campaign_archive(campaign_id)
                    logger.info("Generated campaign archive: %s", archive_path)
            except Exception as exc:
                logger.error("Failed to generate evidence package: %s", exc)

        backend_tasks = []
        for backend in campaign.shared_backends:
            if "digitalocean" in backend.lower():
                backend_tasks.append(
                    self._report_backend(
                        backend=backend,
                        campaign=campaign,
                        platform="digitalocean",
                        dry_run=dry_run,
                        dry_run_email=dry_run_email,
                    )
                )
            elif "vercel" in backend.lower():
                logger.info("Vercel backend detected but no reporter implemented: %s", backend)

        if backend_tasks:
            backend_results = await asyncio.gather(*backend_tasks, return_exceptions=True)
            for result in backend_results:
                if isinstance(result, Exception):
                    results["backends"].append(
                        ReportResult(
                            platform="backend",
                            status=ReportStatus.FAILED,
                            message=str(result),
                        )
                    )
                else:
                    results["backends"].append(result)

        blocklist_platforms = ["google", "netcraft"]
        if platforms:
            blocklist_platforms = [p for p in blocklist_platforms if p in platforms]

        for member in campaign.members:
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
            for result in blocklist_results.values():
                results["blocklists"].append(result)

        # 3. Report to registrars (grouped by registrar)
        # TODO: Group domains by registrar and send bulk reports

        frontend_platforms = [
            p for p in (platforms or self.get_available_platforms()) if p not in blocklist_platforms
        ]

        for member in campaign.members:
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
            for result in frontend_results.values():
                results["frontends"].append(result)

        return results

    async def _report_backend(
        self,
        backend: str,
        campaign: "ThreatCampaign",
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

        if not campaign.members:
            return ReportResult(
                platform=platform,
                status=ReportStatus.FAILED,
                message="No domains in campaign",
            )

        primary_domain = campaign.members[0].domain
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

        evidence.backend_domains = list(campaign.shared_backends)

        if dry_run:
            report_content = self._build_platform_report_preview(platform, evidence)
            report_content = f"""
CAMPAIGN CONTEXT
================
This backend is part of campaign: {campaign.name}
Total domains using this backend: {len(campaign.members)}
Domains: {', '.join(m.domain for m in campaign.members[:10])}{'...' if len(campaign.members) > 10 else ''}

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

        result = await reporter.submit(evidence)
        result.platform = f"{platform}_backend"
        return result
