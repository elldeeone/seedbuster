"""Report retry worker."""

from __future__ import annotations

import asyncio
import logging

from ..utils.domains import extract_first_url

logger = logging.getLogger(__name__)


class SeedBusterPipelineReportingMixin:
    """Background report retry helpers."""

    async def _report_retry_worker(self):
        """Retry rate-limited reports in the background."""
        logger.info("Report retry worker started")

        interval_seconds = 300

        while self._running:
            try:
                results = await self.report_manager.retry_due_reports(limit=20)
                if results:
                    by_status: dict[str, int] = {}
                    for r in results:
                        by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
                    logger.info("Report retry pass: %s", by_status)

                    notify_statuses = {"submitted", "confirmed", "duplicate", "manual_required"}
                    notify = [r for r in results if r.status.value in notify_statuses]
                    if notify:
                        lines = ["*Report retry updates:*"]
                        max_items = 10
                        for r in notify[:max_items]:
                            domain = (r.response_data or {}).get("domain") or "unknown"
                            line = f"- `{domain}`: `{r.platform}` `{r.status.value}`"
                            if r.status.value == "manual_required" and r.message:
                                manual_url = extract_first_url(r.message or "")
                                if manual_url:
                                    line += f" (manual: `{manual_url}`)"
                                try:
                                    short_id = self.evidence_store.get_domain_id(domain)
                                    line += f" (instructions: `/evidence {short_id}`)"
                                except Exception:
                                    pass
                            lines.append(line)
                        extra = len(notify) - max_items
                        if extra > 0:
                            lines.append(f"...and {extra} more")
                        await self.bot.send_message("\n".join(lines))

                await asyncio.sleep(interval_seconds)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Report retry worker error: %s", exc)
                await asyncio.sleep(60)

        logger.info("Report retry worker stopped")
