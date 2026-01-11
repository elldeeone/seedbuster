"""Admin action handlers for domain operations."""

from __future__ import annotations

from aiohttp import web

from ..storage.database import DomainStatus, Verdict
from .server_helpers import _coerce_int
from .server_render_sections import _build_query_link


class DashboardServerAdminActionsMixin:
    """Admin domain action handlers."""

    async def _admin_update_domain(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        data = await self._require_csrf(request)
        status = (data.get("status") or "").strip().lower()
        verdict = (data.get("verdict") or "").strip().lower()
        notes = (data.get("notes") or "").strip()

        if status and status not in {s.value for s in DomainStatus}:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg="Invalid status", error=1)
            )
        if verdict and verdict not in {v.value for v in Verdict}:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg="Invalid verdict", error=1)
            )

        await self.database.update_domain_admin_fields(
            did,
            status=status or None,
            verdict=verdict or None,
            operator_notes=notes,
        )
        raise web.HTTPSeeOther(location=_build_query_link(f"/admin/domains/{did}", msg="Saved"))

    async def _admin_report_domain(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        if not self.report_callback:
            raise web.HTTPSeeOther(
                location=_build_query_link(
                    f"/admin/domains/{did}",
                    msg="Reporting not configured",
                    error=1,
                )
            )

        data = await self._require_csrf(request)
        platforms = list({p.strip().lower() for p in data.getall("platform", []) if p.strip()})
        force = (data.get("force") or "") in {"1", "true", "on", "yes"}

        domain_name = str(domain.get("domain") or "")
        try:
            await self.report_callback(did, domain_name, platforms or None, force)
        except Exception as exc:
            raise web.HTTPSeeOther(
                location=_build_query_link(
                    f"/admin/domains/{did}",
                    msg=f"Report failed: {exc}",
                    error=1,
                )
            )

        platform_info = self.get_platform_info() if self.get_platform_info else {}
        manual_platforms = [
            p for p in platforms if platform_info.get(p, {}).get("manual_only", False)
        ]

        if manual_platforms:
            raise web.HTTPSeeOther(
                location=_build_query_link(
                    f"/admin/domains/{did}",
                    msg="Reports submitted - action required for manual platforms",
                    manual_pending=",".join(manual_platforms),
                )
            )
        raise web.HTTPSeeOther(
            location=_build_query_link(f"/admin/domains/{did}", msg="Reports submitted")
        )

    async def _admin_manual_done(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        if not self.mark_manual_done_callback:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg="Not configured", error=1)
            )

        data = await self._require_csrf(request)
        note = (data.get("note") or "").strip() or "Manual submission marked complete"
        domain_name = str(domain.get("domain") or "")
        try:
            await self.mark_manual_done_callback(did, domain_name, None, note)
        except Exception as exc:
            raise web.HTTPSeeOther(
                location=_build_query_link(
                    f"/admin/domains/{did}",
                    msg=f"Failed: {exc}",
                    error=1,
                )
            )
        raise web.HTTPSeeOther(location=_build_query_link(f"/admin/domains/{did}", msg="Updated"))

    async def _admin_rescan(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")
        await self._require_csrf(request)

        domain_name = str(domain.get("domain") or "")
        if self.rescan_callback:
            already = await self.database.has_pending_dashboard_action("rescan_domain", domain_name)
            if already:
                raise web.HTTPSeeOther(
                    location=_build_query_link(f"/admin/domains/{did}", msg="Rescan already queued")
                )
            self.rescan_callback(domain_name)
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg="Rescan queued")
            )
        raise web.HTTPSeeOther(
            location=_build_query_link(f"/admin/domains/{did}", msg="Rescan not configured", error=1)
        )

    async def _admin_false_positive(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")
        await self._require_csrf(request)

        await self.database.update_domain_admin_fields(
            did,
            status=DomainStatus.FALSE_POSITIVE.value,
            verdict=Verdict.BENIGN.value,
            operator_notes=(domain.get("operator_notes") or ""),
        )
        raise web.HTTPSeeOther(
            location=_build_query_link(f"/admin/domains/{did}", msg="Marked false positive")
        )
