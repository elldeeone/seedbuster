"""Stats and health helpers for dashboard server."""

from __future__ import annotations

import os
import time
from pathlib import Path

import aiohttp


class DashboardServerStatsMixin:
    """Stats and health helpers."""

    async def _get_stats_cached(self, *, include_evidence: bool = False) -> dict:
        cache_key = "admin" if include_evidence else "public"
        now = time.time()
        cached = self._stats_cache.get(cache_key)
        if cached and (now - cached[0]) < self._stats_cache_ttl_seconds:
            return dict(cached[1])

        stats = await self.database.get_stats()
        if include_evidence:
            stats["evidence_bytes"] = self._compute_evidence_bytes()
        self._stats_cache[cache_key] = (now, dict(stats))
        return stats

    def _compute_evidence_bytes(self) -> int:
        total = 0
        for root, _dirs, files in os.walk(self.evidence_dir):
            for name in files:
                try:
                    total += (Path(root) / name).stat().st_size
                except OSError:
                    continue
        return total

    async def _fetch_health_status(self) -> dict | None:
        url = getattr(self.config, "health_url", "") or ""
        url = url.strip()
        if not url:
            return None
        try:
            session = await self._get_http_session()
            timeout = aiohttp.ClientTimeout(total=2)
            async with session.get(url, timeout=timeout) as resp:
                try:
                    payload = await resp.json(content_type=None)
                except Exception:
                    payload = {"body": await resp.text()}
                return {
                    "ok": resp.status == 200,
                    "status": payload.get("status") if isinstance(payload, dict) else None,
                    "data": payload,
                }
        except Exception as exc:  # pragma: no cover - best-effort
            return {"ok": False, "error": str(exc)}
