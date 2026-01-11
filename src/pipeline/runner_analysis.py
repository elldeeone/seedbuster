"""Analysis worker helpers."""

from __future__ import annotations

import asyncio
import logging

from ..analyzer.temporal import ScanReason

logger = logging.getLogger(__name__)


class SeedBusterPipelineAnalysisMixin:
    """Analyze queued domains for phishing signals."""

    async def _analysis_worker(self, worker_id: int | None = None):
        """Analyze queued domains for phishing signals."""
        label = f"Analysis worker {worker_id}" if worker_id else "Analysis worker"
        logger.info("%s started", label)

        while self._running:
            try:
                try:
                    task = await asyncio.wait_for(
                        self._analysis_queue.get(),
                        timeout=1.0,
                    )
                except asyncio.TimeoutError:
                    continue

                if isinstance(task, tuple):
                    domain = task[0] if len(task) > 0 else ""
                    scan_reason = task[1] if len(task) > 1 else ScanReason.MANUAL
                    source_url = task[2] if len(task) > 2 else None
                    domain_record = await self.database.get_domain(domain)

                    try:
                        if domain_record:
                            domain_id = int(domain_record.get("id") or 0)
                            score_result = self.scorer.score_domain(domain)
                            domain_score = score_result.score
                            domain_reasons = score_result.reasons
                            if domain_id:
                                current_score = int(domain_record.get("domain_score") or 0)
                                if domain_score != current_score:
                                    await self.database.update_domain_score(domain_id, domain_score)
                            domain_record["domain_score"] = domain_score
                            domain_record["reasons"] = domain_reasons
                            if source_url:
                                domain_record["source_url"] = source_url
                            await self.analysis_engine.analyze(domain_record, scan_reason=scan_reason)
                        else:
                            logger.warning("Rescan: domain not found in DB: %s", domain)
                    finally:
                        key = (domain or "").strip().lower()
                        if key:
                            self._rescan_pending.discard(key)
                else:
                    await self.analysis_engine.analyze(task)

            except Exception as exc:
                logger.error("Analysis worker error: %s", exc)
                await asyncio.sleep(1)

    async def _analyze_domain(self, task: dict, scan_reason: ScanReason = ScanReason.INITIAL):
        """Delegate to AnalysisEngine (moved to pipeline.analysis)."""
        await self.analysis_engine.analyze(task, scan_reason=scan_reason)
