"""Admin stats API handlers."""

from __future__ import annotations

from aiohttp import web

from .server_helpers import _coerce_int


class DashboardServerAdminApiStatsMixin:
    """Admin stats and analytics API."""

    async def _admin_api_stats(self, request: web.Request) -> web.Response:
        stats = await self._get_stats_cached(include_evidence=True)
        stats["public_submissions_pending"] = await self.database.count_public_submissions(status="pending_review")
        pending_reports = await self.database.get_pending_reports()
        health_status = await self._fetch_health_status()
        return web.json_response({"stats": stats, "pending_reports": pending_reports, "health": health_status})

    async def _admin_api_takedown_checks(self, request: web.Request) -> web.Response:
        domain_id = (request.query.get("domain_id") or "").strip()
        domain_query = (request.query.get("domain") or request.query.get("q") or "").strip()
        exclude_statuses_raw = (request.query.get("exclude_statuses") or "").strip().lower()
        status = (request.query.get("status") or "").strip().lower()
        signal = (
            request.query.get("signal")
            or request.query.get("provider_signal")
            or ""
        ).strip()
        backend_only = (request.query.get("backend_only") or "").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        since = (request.query.get("since") or "").strip()
        until = (request.query.get("until") or "").strip()

        limit = _coerce_int(
            request.query.get("limit"),
            default=100,
            min_value=1,
            max_value=500,
        )
        offset = _coerce_int(
            request.query.get("offset"),
            default=0,
            min_value=0,
            max_value=1_000_000,
        )

        domain_id_value = None
        if domain_id:
            try:
                domain_id_value = int(domain_id)
            except ValueError:
                raise web.HTTPBadRequest(text="domain_id must be an integer")

        if "exclude_statuses" in request.query:
            exclude_statuses = [s.strip() for s in exclude_statuses_raw.split(",") if s.strip()]
        else:
            exclude_statuses = ["allowlisted", "false_positive"]

        rows = await self.database.get_takedown_checks(
            domain_id=domain_id_value,
            domain_query=domain_query or None,
            exclude_statuses=exclude_statuses,
            limit=limit,
            offset=offset,
            status=status or None,
            provider_signal=signal or None,
            backend_only=backend_only,
            since=since or None,
            until=until or None,
        )
        return web.json_response({
            "checks": rows,
            "count": len(rows),
            "limit": limit,
            "offset": offset,
        })

    async def _admin_api_analytics(self, request: web.Request) -> web.Response:
        """Return engagement + takedown analytics (admin-only)."""
        engagement = await self.database.get_engagement_summary()
        takedown = await self.database.get_takedown_metrics()
        return web.json_response({"engagement": engagement, "takedown": takedown})

    async def _admin_api_detection_metrics(self, request: web.Request) -> web.Response:
        """Return detection pattern metrics (admin-only)."""
        from ..analyzer.metrics import metrics
        return web.json_response(metrics.get_summary())

    async def _admin_api_platforms(self, request: web.Request) -> web.Response:
        """Return available reporting platforms with their metadata."""
        platforms = self.get_available_platforms()
        info = self.get_platform_info()
        return web.json_response({"platforms": platforms, "info": info})
