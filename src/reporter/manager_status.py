"""Report status helpers."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from .base import ReportResult, ReportStatus

logger = logging.getLogger(__name__)


class ReportManagerStatusMixin:
    """Report status and approval helpers."""

    async def get_report_status(self, domain_id: int) -> list[dict]:
        """Get all report statuses for a domain."""
        return await self.database.get_reports_for_domain(domain_id)

    async def get_pending_approvals(self) -> list[dict]:
        """Get domains awaiting report approval."""
        return await self.database.get_pending_reports()

    async def approve_report(self, domain_id: int, domain: str) -> dict[str, ReportResult]:
        """Approve and submit reports for a domain."""
        return await self.report_domain(domain_id, domain)

    async def reject_report(self, domain_id: int, reason: str = "false_positive") -> None:
        """Reject a report (mark as false positive)."""
        await self.database.update_domain_status(
            domain_id,
            status="false_positive",
            verdict="benign",
        )
        logger.info("Report rejected for domain %s: %s", domain_id, reason)

    async def mark_manual_done(
        self,
        domain_id: int,
        domain: str,
        platforms: Optional[list[str]] = None,
        *,
        note: str = "Manual submission marked complete",
    ) -> dict[str, ReportResult]:
        """Mark MANUAL_REQUIRED reports as completed (SUBMITTED)."""
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
        marker = (
            f"{note} at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} "
            "UTC (SeedBuster operator)"
        )

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
                response = (
                    (prev_response.rstrip() + "\n\n" + marker).strip()
                    if prev_response.strip()
                    else marker
                )

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
