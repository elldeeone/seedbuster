"""Rescan scheduling helpers."""

from __future__ import annotations

import asyncio
import logging
import os

from ..analyzer.temporal import ScanReason
from ..storage.database import DomainStatus

logger = logging.getLogger(__name__)


class SeedBusterPipelineRescanMixin:
    """Rescan scheduling helpers."""

    async def _handle_rescan(
        self,
        domain: str,
        reason: ScanReason,
        source_url: str | None = None,
    ):
        """Handle scheduled rescan - re-analyze domain and send update if changed."""
        logger.info("Rescan triggered for %s (reason: %s)", domain, reason.value)

        rescan_key = (domain or "").strip().lower()
        if rescan_key in self._rescan_pending:
            logger.info("Rescan already queued for %s; skipping duplicate.", domain)
            return

        domain_record = await self.database.get_domain(domain)
        if domain_record:
            status = str(domain_record.get("status") or "").strip().lower()
            benign_statuses = {
                DomainStatus.FALSE_POSITIVE.value,
                DomainStatus.ALLOWLISTED.value,
            }
            if status in benign_statuses and reason != ScanReason.MANUAL:
                canceled = self.temporal.cancel_rescans(domain)
                logger.info(
                    "Skipping scheduled rescan for %s (status=%s); canceled %s remaining rescans",
                    domain,
                    status,
                    canceled,
                )
                return
            domain = str(domain_record.get("domain") or domain)
            rescan_key = (domain or "").strip().lower() or rescan_key

        if rescan_key:
            self._rescan_pending.add(rescan_key)
        try:
            task = (domain, reason, source_url) if source_url else (domain, reason)
            await self._analysis_queue.put(task)
        except Exception:
            if rescan_key:
                self._rescan_pending.discard(rescan_key)
            raise

    async def _watchlist_rescan_worker(self):
        """Periodically rescan watchlist domains."""
        logger.info("Watchlist rescan worker started")

        rescan_days = int(os.environ.get("WATCHLIST_RESCAN_DAYS", "30"))
        check_interval_seconds = 6 * 60 * 60

        while self._running:
            try:
                domains = await self.database.get_watchlist_domains_due_rescan(
                    days_since_update=rescan_days,
                    limit=10,
                )

                if domains:
                    logger.info("Found %s watchlist domains due for rescan", len(domains))

                for row in domains:
                    domain = str(row.get("domain") or "").strip()
                    if not domain:
                        continue

                    logger.info("Queueing monthly rescan for watchlist domain: %s", domain)
                    await self._handle_rescan(domain, ScanReason.RESCAN_MONTHLY)

                await asyncio.sleep(check_interval_seconds)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Watchlist rescan worker error: %s", exc)
                await asyncio.sleep(60)

        logger.info("Watchlist rescan worker stopped")
