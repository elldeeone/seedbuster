"""Discovery and dashboard action workers."""

from __future__ import annotations

import asyncio
import json
import logging

from ..utils.domains import canonicalize_domain, normalize_source_url

logger = logging.getLogger(__name__)


class SeedBusterPipelineDiscoveryMixin:
    """Discovery queue + dashboard action handling."""

    async def _discovery_worker(self):
        """Process discovered domains from CT stream."""
        logger.info("Discovery worker started")

        while self._running:
            try:
                try:
                    item = await asyncio.wait_for(
                        self._discovery_queue.get(),
                        timeout=1.0,
                    )
                except asyncio.TimeoutError:
                    continue

                source = "certstream"
                force = False
                source_url = None
                if isinstance(item, dict):
                    domain = (item.get("domain") or "").strip()
                    source = (item.get("source") or source).strip() or source
                    force = bool(item.get("force", False))
                    source_url = (item.get("source_url") or "").strip() or None
                else:
                    domain = str(item).strip()

                if not domain:
                    continue

                if await self.database.domain_exists(domain):
                    logger.debug("Already seen: %s", domain)
                    continue

                score_result = self.scorer.score_domain(domain)

                if score_result.is_allowlisted:
                    logger.debug("Allowlisted: %s", domain)
                    continue

                if not force and not score_result.should_analyze:
                    logger.debug("Below threshold: %s (score=%s)", domain, score_result.score)
                    continue

                domain_id = await self.database.add_domain(
                    domain=domain,
                    source=source,
                    domain_score=score_result.score,
                    source_url=source_url,
                )

                if domain_id:
                    logger.info(
                        "Queued for analysis: %s (score=%s, reasons=%s)",
                        domain,
                        score_result.score,
                        score_result.reasons,
                    )
                    await self._analysis_queue.put({
                        "id": domain_id,
                        "domain": domain,
                        "domain_score": score_result.score,
                        "reasons": score_result.reasons,
                        "source_url": source_url,
                    })

            except Exception as exc:
                logger.error("Discovery worker error: %s", exc)
                await asyncio.sleep(1)

    async def _dashboard_actions_worker(self):
        """Process dashboard admin actions (submit/rescan/report) from SQLite queue."""
        logger.info("Dashboard actions worker started")

        while self._running:
            try:
                actions = await self.database.claim_dashboard_actions(limit=20)
                if not actions:
                    await asyncio.sleep(1.0)
                    continue

                for action in actions:
                    action_id = int(action.get("id") or 0)
                    kind = str(action.get("kind") or "").strip().lower()
                    payload_raw = action.get("payload") or "{}"

                    try:
                        payload = (
                            json.loads(payload_raw)
                            if isinstance(payload_raw, str) and payload_raw.strip()
                            else {}
                        )
                    except Exception:
                        payload = {}

                    try:
                        await self._handle_dashboard_action(kind, payload)
                        await self.database.finish_dashboard_action(action_id, status="done")
                    except Exception as exc:
                        logger.warning(
                            "Dashboard action failed (id=%s kind=%s): %s",
                            action_id,
                            kind,
                            exc,
                        )
                        await self.database.finish_dashboard_action(
                            action_id,
                            status="failed",
                            error=str(exc),
                        )

            except Exception as exc:
                logger.error("Dashboard actions worker error: %s", exc)
                await asyncio.sleep(1.0)

    async def _handle_dashboard_action(self, kind: str, payload: dict) -> None:
        """Handle a single dashboard action payload."""
        action = str(kind or "").strip().lower()

        if action == "submit_domain":
            domain = str(payload.get("domain") or "").strip().lower()
            if not domain:
                raise ValueError("domain is required")
            canonical = canonicalize_domain(domain) or domain
            domain = canonical

            source_url = normalize_source_url(payload.get("source_url"), canonical=canonical)

            if await self.database.domain_exists(domain):
                if source_url:
                    self._manual_rescan(domain, source_url=source_url)
                else:
                    self._manual_rescan(domain)
                return

            try:
                self._discovery_queue.put_nowait({
                    "domain": domain,
                    "source": "manual",
                    "force": True,
                    "source_url": source_url,
                })
            except asyncio.QueueFull:
                raise RuntimeError("discovery queue full")

            return

        if action == "rescan_domain":
            domain = str(payload.get("domain") or "").strip().lower()
            if not domain:
                raise ValueError("domain is required")
            self._manual_rescan(domain)
            return

        if action == "report_domain":
            domain_id = int(payload.get("domain_id") or 0)
            domain = str(payload.get("domain") or "").strip()
            force = bool(payload.get("force", False))
            platforms = payload.get("platforms")
            platforms_list: list[str] | None = None
            if isinstance(platforms, list):
                platforms_list = [str(p).strip().lower() for p in platforms if str(p).strip()]

            if not domain and domain_id:
                row = await self.database.get_domain_by_id(domain_id)
                domain = str(row.get("domain") or "").strip() if row else ""
            if not domain_id and domain:
                row = await self.database.get_domain(domain)
                domain_id = int(row.get("id") or 0) if row else 0

            if not domain_id or not domain:
                raise ValueError("domain_id/domain required")

            await self.report_manager.report_domain(
                domain_id=domain_id,
                domain=domain,
                platforms=platforms_list,
                force=force,
            )
            return

        if action == "manual_done":
            domain_id = int(payload.get("domain_id") or 0)
            domain = str(payload.get("domain") or "").strip()
            platforms = payload.get("platforms")
            platforms_list: list[str] | None = None
            if isinstance(platforms, list):
                platforms_list = [str(p).strip().lower() for p in platforms if str(p).strip()]
            note = str(payload.get("note") or "Manual submission marked complete").strip()

            if not domain and domain_id:
                row = await self.database.get_domain_by_id(domain_id)
                domain = str(row.get("domain") or "").strip() if row else ""
            if not domain_id and domain:
                row = await self.database.get_domain(domain)
                domain_id = int(row.get("id") or 0) if row else 0

            if not domain_id or not domain:
                raise ValueError("domain_id/domain required")

            await self.report_manager.mark_manual_done(
                domain_id=domain_id,
                domain=domain,
                platforms=platforms_list,
                note=note,
            )
            return

        if action == "allowlist_add":
            domain = str(payload.get("domain") or "").strip().lower()
            if not domain:
                raise ValueError("domain is required")
            self._allowlist_add(domain)
            return

        if action == "allowlist_remove":
            domain = str(payload.get("domain") or "").strip().lower()
            if not domain:
                raise ValueError("domain is required")
            self._allowlist_remove(domain)
            return

        raise ValueError(f"unknown action kind: {action}")
