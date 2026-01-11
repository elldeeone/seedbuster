"""Takedown monitoring helpers."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..analyzer.takedown_checker import TakedownStatus
from ..analyzer.temporal import ScanReason

logger = logging.getLogger(__name__)


class SeedBusterPipelineTakedownMixin:
    """Takedown monitoring helpers."""

    @staticmethod
    def _parse_timestamp(value: str | None):
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def _takedown_interval_seconds(self, row: dict, now: datetime) -> int:
        """Compute how often to check based on age/status."""
        status = str(row.get("takedown_status") or "active").lower()
        reported_at = (
            self._parse_timestamp(row.get("reported_at"))
            or self._parse_timestamp(row.get("created_at"))
            or now
        )
        age_hours = max(0.0, (now - reported_at).total_seconds() / 3600.0)

        if status == TakedownStatus.CONFIRMED_DOWN.value:
            hours = max(1, int(self.config.takedown_interval_confirmed_down_hours or 6))
            return hours * 60 * 60
        if status == TakedownStatus.LIKELY_DOWN.value:
            minutes = max(1, int(self.config.takedown_interval_likely_down_minutes or 30))
            return minutes * 60
        if age_hours < 24:
            minutes = max(1, int(self.config.takedown_interval_new_minutes or 15))
            return minutes * 60
        if age_hours < 24 * 7:
            hours = max(1, int(self.config.takedown_interval_week_hours or 1))
            return hours * 60 * 60
        hours = max(1, int(self.config.takedown_interval_older_hours or 3))
        return hours * 60 * 60

    @staticmethod
    def _takedown_recovered(
        previous_status: str | None,
        current_status: TakedownStatus,
    ) -> bool:
        prev = str(previous_status or "").strip().lower()
        if not prev:
            return False
        if current_status != TakedownStatus.ACTIVE:
            return False
        return prev in {
            TakedownStatus.LIKELY_DOWN.value,
            TakedownStatus.CONFIRMED_DOWN.value,
        }

    async def _takedown_worker(self):
        """Monitor domains for takedown signals (DNS/HTTP)."""
        logger.info("Takedown monitor worker started")
        while self._running:
            try:
                batch_size = max(1, int(self.config.takedown_check_batch_size or 200))
                concurrency = max(1, int(self.config.takedown_check_concurrency or 10))
                domains = await self.database.get_domains_for_takedown_check(limit=batch_size)
                now = datetime.now(timezone.utc)
                due_rows = []
                for row in domains:
                    domain = str(row.get("domain") or "").strip()
                    if not domain:
                        continue

                    last_checked = self._parse_timestamp(row.get("last_checked_at"))
                    interval = self._takedown_interval_seconds(row, now)
                    if last_checked and (now - last_checked).total_seconds() < interval:
                        continue
                    due_rows.append(row)

                if not due_rows:
                    await asyncio.sleep(300)
                    continue

                semaphore = asyncio.Semaphore(concurrency)

                async def _check_row(row: dict) -> int:
                    async with semaphore:
                        domain = str(row.get("domain") or "").strip()
                        if not domain:
                            return 0
                        try:
                            check_time = datetime.now(timezone.utc)
                            analysis = None
                            evidence_path = row.get("evidence_path")
                            analysis_path = None
                            if evidence_path:
                                analysis_path = Path(str(evidence_path)) / "analysis.json"
                            if not analysis_path or not analysis_path.exists():
                                analysis_path = self.evidence_store.get_analysis_path(domain)
                            if analysis_path and analysis_path.exists():
                                try:
                                    analysis = json.loads(
                                        analysis_path.read_text(encoding="utf-8")
                                    )
                                except Exception:
                                    analysis = None

                            result = await self.takedown_checker.check(domain, analysis=analysis)
                            await self.database.add_takedown_check(
                                domain_id=int(row.get("id") or 0),
                                domain=domain,
                                status=result.status.value,
                                checked_at=check_time.isoformat(),
                                provider_signal=result.provider_signal,
                                backend_status=result.backend_status,
                                backend_error=result.backend_error,
                                backend_target=result.backend_target,
                            )
                            if self._takedown_recovered(row.get("takedown_status"), result.status):
                                await self._handle_rescan(domain, ScanReason.CONTENT_CHANGE)
                                logger.info(
                                    "Takedown recovery detected for %s; rescan queued",
                                    domain,
                                )
                            if bool(row.get("takedown_override")):
                                return 1

                            detected_at = None
                            confirmed_at = None
                            if result.status in {TakedownStatus.LIKELY_DOWN, TakedownStatus.CONFIRMED_DOWN}:
                                detected_at = check_time.isoformat()
                            if result.status == TakedownStatus.CONFIRMED_DOWN:
                                confirmed_at = check_time.isoformat()

                            await self.database.update_domain_takedown_status(
                                int(row.get("id") or 0),
                                result.status.value,
                                detected_at=detected_at,
                                confirmed_at=confirmed_at,
                            )
                            return 1
                        except Exception as exc:
                            logger.error("Takedown check failed for %s: %s", domain, exc)
                            return 0

                results = await asyncio.gather(*[_check_row(row) for row in due_rows])
                checked = sum(results)
                await asyncio.sleep(60 if checked else 300)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Takedown worker error: %s", exc)
                await asyncio.sleep(120)

        logger.info("Takedown monitor worker stopped")
