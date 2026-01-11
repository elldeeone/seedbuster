"""Evidence cleanup helpers."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime

from aiohttp import web


class DashboardServerMaintenanceMixin:
    """Evidence retention helpers."""

    def _collect_old_evidence(self, days: int) -> list[dict]:
        """Gather evidence directories older than N days with metadata."""
        from datetime import timedelta, timezone

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        candidates: list[dict] = []
        for domain_dir in self.evidence_dir.iterdir():
            if not domain_dir.is_dir():
                continue
            analysis_path = domain_dir / "analysis.json"
            if not analysis_path.exists():
                continue
            try:
                data = json.loads(analysis_path.read_text())
                saved_at = data.get("saved_at")
                if not saved_at:
                    continue
                ts = datetime.fromisoformat(saved_at)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts < cutoff:
                    size = 0
                    try:
                        for p in domain_dir.rglob("*"):
                            if p.is_file():
                                size += p.stat().st_size
                    except Exception:
                        pass
                    candidates.append({"path": domain_dir, "saved_at": ts, "size": size})
            except Exception:
                continue
        return candidates

    async def _admin_api_cleanup_evidence(self, request: web.Request) -> web.Response:
        self._require_csrf_header(request)
        data = await self._read_json(request)
        days = int(data.get("days") or 30)
        if days < 1:
            days = 1
        preview = bool(data.get("preview"))
        loop = asyncio.get_event_loop()
        if preview:
            candidates = await loop.run_in_executor(None, lambda: self._collect_old_evidence(days))
            total_bytes = sum(item.get("size", 0) for item in candidates)
            return web.json_response(
                {
                    "status": "ok",
                    "preview": True,
                    "would_remove": len(candidates),
                    "would_bytes": total_bytes,
                }
            )

        removed, removed_bytes = await loop.run_in_executor(None, lambda: self._cleanup_evidence(days))
        return web.json_response(
            {"status": "ok", "removed_dirs": removed, "removed_bytes": removed_bytes}
        )

    def _cleanup_evidence(self, days: int) -> tuple[int, int]:
        """Remove evidence older than N days. Returns (dirs removed, bytes freed)."""
        import shutil

        removed = 0
        freed_bytes = 0
        for item in self._collect_old_evidence(days):
            try:
                shutil.rmtree(item["path"])
                removed += 1
                freed_bytes += int(item.get("size") or 0)
            except Exception:
                continue
        return removed, freed_bytes
