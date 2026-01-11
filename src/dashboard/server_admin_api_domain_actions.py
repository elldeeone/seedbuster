"""Admin domain action API handlers."""

from __future__ import annotations

from datetime import datetime, timezone

from aiohttp import web

from ..analyzer.takedown_checker import TakedownStatus
from ..storage.database import DomainStatus
from .server_helpers import _coerce_int


class DashboardServerAdminApiDomainActionsMixin:
    """Admin domain action APIs."""

    async def _admin_api_update_domain_status(self, request: web.Request) -> web.Response:
        """Update domain status (PATCH /admin/api/domains/{domain_id}/status)."""
        self._require_csrf_header(request)
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        data = await self._read_json(request)
        new_status = (data.get("status") or "").strip().lower()

        valid_statuses = {s.value for s in DomainStatus}
        if new_status not in valid_statuses:
            return web.json_response(
                {"error": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"},
                status=400,
            )

        await self.database.update_domain_status(domain_id, DomainStatus(new_status))
        return web.json_response({"status": "ok", "new_status": new_status})

    async def _admin_api_update_domain_takedown_status(self, request: web.Request) -> web.Response:
        """Update takedown status (PATCH /admin/api/domains/{domain_id}/takedown)."""
        self._require_csrf_header(request)
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        data = await self._read_json(request)
        new_status = (data.get("status") or "").strip().lower()

        valid_statuses = {s.value for s in TakedownStatus}
        if new_status not in valid_statuses:
            return web.json_response(
                {"error": f"Invalid status. Must be one of: {', '.join(sorted(valid_statuses))}"},
                status=400,
            )

        now = datetime.now(timezone.utc).isoformat()
        detected_at = None
        confirmed_at = None
        clear_timestamps = False
        if new_status in {TakedownStatus.LIKELY_DOWN.value, TakedownStatus.CONFIRMED_DOWN.value}:
            detected_at = now
            if new_status == TakedownStatus.CONFIRMED_DOWN.value:
                confirmed_at = now
        elif new_status == TakedownStatus.ACTIVE.value:
            clear_timestamps = True

        await self.database.update_domain_takedown_status(
            domain_id,
            new_status,
            detected_at=detected_at,
            confirmed_at=confirmed_at,
            clear_timestamps=clear_timestamps,
        )
        await self.database.set_takedown_override(domain_id, enabled=True, override_at=now)
        return web.json_response(
            {
                "status": "ok",
                "takedown_status": new_status,
                "takedown_override": True,
            }
        )

    async def _admin_api_update_domain_takedown_override(self, request: web.Request) -> web.Response:
        """Update takedown override flag (PATCH /admin/api/domains/{domain_id}/takedown-override)."""
        self._require_csrf_header(request)
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        data = await self._read_json(request)
        enabled = bool(data.get("enabled"))
        override_at = datetime.now(timezone.utc).isoformat() if enabled else None

        await self.database.set_takedown_override(
            domain_id,
            enabled=enabled,
            override_at=override_at,
        )
        return web.json_response({"status": "ok", "takedown_override": enabled})

    async def _admin_api_update_notes(self, request: web.Request) -> web.Response:
        """Update operator notes for a domain (PATCH /admin/api/domains/{domain_id}/notes)."""
        self._require_csrf_header(request)
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        domain = await self.database.get_domain_by_id(domain_id)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found")

        data = await self._read_json(request)
        notes = data.get("notes", "")

        await self.database.update_domain_admin_fields(
            domain_id,
            operator_notes=notes,
        )
        return web.json_response({"status": "ok"})

    async def _admin_api_update_baseline(self, request: web.Request) -> web.Response:
        """Update watchlist baseline to current snapshot (POST /admin/api/domains/{domain_id}/baseline)."""
        self._require_csrf_header(request)
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        domain_record = await self.database.get_domain_by_id(domain_id)
        if not domain_record:
            return web.json_response({"error": "Domain not found"}, status=404)

        if domain_record.get("status") != "watchlist":
            return web.json_response(
                {"error": "Domain must be in watchlist status to update baseline"},
                status=400,
            )

        new_baseline = await self.database.update_watchlist_baseline(domain_id)
        if not new_baseline:
            return web.json_response({"error": "Failed to update baseline"}, status=500)

        domain_name = domain_record.get("domain")
        latest_snapshot = self.temporal.get_latest_snapshot(domain_name)

        response_data = {
            "status": "ok",
            "baseline_timestamp": new_baseline,
        }

        if latest_snapshot:
            response_data["snapshot"] = {
                "score": latest_snapshot.score,
                "verdict": latest_snapshot.verdict,
                "timestamp": latest_snapshot.timestamp.isoformat(),
            }

        return web.json_response(response_data)

    async def _admin_api_false_positive(self, request: web.Request) -> web.Response:
        self._require_csrf_header(request)
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")
        await self.database.mark_false_positive(domain_id)
        return web.json_response({"status": "ok"})

    async def _admin_api_rescan(self, request: web.Request) -> web.Response:
        self._require_csrf_header(request)
        domain_id = int(request.match_info.get("domain_id") or 0)
        domain = (request.match_info.get("domain") or "").strip()
        if not domain and domain_id:
            row = await self.database.get_domain_by_id(domain_id)
            domain = str(row.get("domain") or "") if row else ""
        if not domain:
            raise web.HTTPBadRequest(text="domain not found")

        if not self.rescan_callback:
            raise web.HTTPServiceUnavailable(text="Rescan not configured")
        already = await self.database.has_pending_dashboard_action("rescan_domain", domain)
        if already:
            return web.json_response({"status": "already_queued", "domain": domain})
        self.rescan_callback(domain)
        return web.json_response({"status": "rescan_queued", "domain": domain})

    async def _admin_api_report(self, request: web.Request) -> web.Response:
        self._require_csrf_header(request)
        data = await self._read_json(request)
        domain_id = int(data.get("domain_id") or 0)
        domain = (data.get("domain") or "").strip()
        platforms_raw = data.get("platforms")
        platforms = [p.strip().lower() for p in platforms_raw] if isinstance(platforms_raw, list) else None
        force = bool(data.get("force", False))

        if not domain and domain_id:
            row = await self.database.get_domain_by_id(domain_id)
            domain = str(row.get("domain") or "") if row else ""
        if not domain_id and domain:
            row = await self.database.get_domain(domain)
            domain_id = int(row.get("id") or 0) if row else 0

        if not domain_id or not domain:
            raise web.HTTPBadRequest(text="domain_id/domain required")
        if not self.report_callback:
            raise web.HTTPServiceUnavailable(text="Report callback not configured")

        await self.report_callback(domain_id, domain, platforms, force)
        return web.json_response({"status": "report_enqueued", "domain": domain, "platforms": platforms})

    async def _admin_api_report_options(self, request: web.Request) -> web.Response:
        """Return manual report options for admin (prefilled)."""
        domain_id = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        domain = await self.database.get_domain_by_id(domain_id)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found")
        takedown_status = str(domain.get("takedown_status") or "").strip().lower()
        if takedown_status == "confirmed_down":
            return web.json_response(
                {"error": "Domain marked as taken down; reporting is paused."},
                status=409,
            )

        platform_info = self.get_platform_info()
        available_platforms = self.get_available_platforms()
        if not available_platforms:
            return web.json_response({"error": "No reporting platforms configured"}, status=503)

        manual_data: dict[str, dict] = {}
        if self.get_manual_report_options:
            try:
                manual_data = await self.get_manual_report_options(
                    domain_id,
                    domain.get("domain", ""),
                    available_platforms,
                    public=False,
                )
            except Exception as e:
                raise web.HTTPServiceUnavailable(text=f"Manual instructions unavailable: {e}")
        else:
            raise web.HTTPServiceUnavailable(text="Manual instructions not configured")

        engagement_counts = await self.database.get_report_engagement_counts(domain_id)
        total_engagements = sum(engagement_counts.get(p, 0) for p in manual_data.keys())

        entries = []
        for platform in manual_data.keys():
            info = platform_info.get(platform, {}) if isinstance(platform_info, dict) else {}
            raw_instruction = manual_data.get(platform)
            instructions = None
            error = None
            if isinstance(raw_instruction, dict):
                if set(raw_instruction.keys()) == {"error"}:
                    error = str(raw_instruction.get("error"))
                else:
                    instructions = raw_instruction
            entries.append(
                {
                    "id": platform,
                    "name": info.get("name") or " ".join(part.capitalize() for part in platform.split("_")),
                    "manual_only": bool(info.get("manual_only", True)),
                    "url": info.get("url", ""),
                    "engagement_count": engagement_counts.get(platform, 0),
                    "instructions": instructions,
                    "error": error,
                }
            )

        return web.json_response(
            {
                "domain": domain.get("domain"),
                "domain_id": domain_id,
                "platforms": entries,
                "total_engagements": total_engagements,
            }
        )
