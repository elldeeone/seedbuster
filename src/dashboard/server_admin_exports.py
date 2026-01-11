"""Admin report/export handlers."""

from __future__ import annotations

from aiohttp import web

from .server_helpers import _coerce_int, _domain_dir_name
from .server_render_sections import _build_query_link


class DashboardServerAdminExportsMixin:
    """Admin report/export endpoints."""

    async def _admin_domain_pdf(self, request: web.Request) -> web.Response:
        """Generate and download PDF report for a domain."""
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        if not self.generate_domain_pdf_callback:
            raise web.HTTPServiceUnavailable(text="PDF generation not configured.")

        domain_name = str(domain.get("domain") or "")
        snapshot_id = None
        snapshot_param = (request.query.get("snapshot") or "").strip()
        if snapshot_param:
            domain_dir = self.evidence_dir / _domain_dir_name(domain_name)
            _snapshots, latest_id = self._list_snapshots(domain_dir)
            snapshot_dir, resolved_snapshot_id, _is_latest = self._resolve_snapshot_dir(
                domain_dir, snapshot_param, latest_id
            )
            if snapshot_param and not snapshot_dir:
                raise web.HTTPNotFound(text="Snapshot not found.")
            snapshot_id = resolved_snapshot_id or latest_id
        try:
            report_path = await self.generate_domain_pdf_callback(domain_name, did, snapshot_id)
            if not report_path or not report_path.exists():
                raise web.HTTPServiceUnavailable(text="PDF generation failed or unavailable.")

            return web.FileResponse(
                report_path,
                headers={
                    "Content-Disposition": (
                        f'attachment; filename="{domain_name.replace(".", "_")}_report{report_path.suffix}"'
                    )
                },
            )
        except Exception as e:
            raise web.HTTPInternalServerError(text=f"PDF generation failed: {e}")

    async def _admin_domain_package(self, request: web.Request) -> web.Response:
        """Generate and download evidence archive for a domain."""
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        if not self.generate_domain_package_callback:
            raise web.HTTPServiceUnavailable(text="Package generation not configured.")

        domain_name = str(domain.get("domain") or "")
        snapshot_id = None
        snapshot_param = (request.query.get("snapshot") or "").strip()
        if snapshot_param:
            domain_dir = self.evidence_dir / _domain_dir_name(domain_name)
            snapshots, latest_id = self._list_snapshots(domain_dir)
            snapshot_dir, resolved_snapshot_id, _is_latest = self._resolve_snapshot_dir(
                domain_dir, snapshot_param, latest_id
            )
            if snapshot_param and not snapshot_dir:
                raise web.HTTPNotFound(text="Snapshot not found.")
            snapshot_id = resolved_snapshot_id or latest_id
        try:
            archive_path = await self.generate_domain_package_callback(domain_name, did, snapshot_id)
            if not archive_path or not archive_path.exists():
                raise web.HTTPServiceUnavailable(text="Archive generation failed.")

            return web.FileResponse(
                archive_path,
                headers={
                    "Content-Disposition": f'attachment; filename="{archive_path.name}"'
                },
            )
        except Exception as e:
            raise web.HTTPInternalServerError(text=f"Package generation failed: {e}")

    async def _admin_domain_preview(self, request: web.Request) -> web.Response:
        """Dry-run report submission for a domain (sends to operator's email)."""
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        await self._require_csrf(request)

        if not self.preview_domain_report_callback:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg="Preview not configured", error=1)
            )

        domain_name = str(domain.get("domain") or "")
        try:
            await self.preview_domain_report_callback(did, domain_name)
        except Exception as e:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/domains/{did}", msg=f"Preview failed: {e}", error=1)
            )

        raise web.HTTPSeeOther(location=_build_query_link(f"/admin/domains/{did}", msg="Preview sent to your email"))

    async def _admin_campaign_pdf(self, request: web.Request) -> web.Response:
        """Generate and download PDF report for a campaign."""
        campaign_id = request.match_info.get("campaign_id", "")
        campaign = self._get_campaign_by_id(campaign_id)
        if not campaign:
            raise web.HTTPNotFound(text="Campaign not found.")

        if not self.generate_campaign_pdf_callback:
            raise web.HTTPServiceUnavailable(text="PDF generation not configured.")

        full_campaign_id = campaign.get("campaign_id", campaign_id)
        try:
            report_path = await self.generate_campaign_pdf_callback(full_campaign_id)
            if not report_path or not report_path.exists():
                raise web.HTTPServiceUnavailable(text="PDF generation failed or unavailable.")

            campaign_name = campaign.get("name", "campaign").replace(" ", "_")
            return web.FileResponse(
                report_path,
                headers={
                    "Content-Disposition": f'attachment; filename="{campaign_name}_report{report_path.suffix}"'
                },
            )
        except Exception as e:
            raise web.HTTPInternalServerError(text=f"PDF generation failed: {e}")

    async def _admin_campaign_package(self, request: web.Request) -> web.Response:
        """Generate and download evidence archive for a campaign."""
        campaign_id = request.match_info.get("campaign_id", "")
        campaign = self._get_campaign_by_id(campaign_id)
        if not campaign:
            raise web.HTTPNotFound(text="Campaign not found.")

        if not self.generate_campaign_package_callback:
            raise web.HTTPServiceUnavailable(text="Package generation not configured.")

        full_campaign_id = campaign.get("campaign_id", campaign_id)
        try:
            archive_path = await self.generate_campaign_package_callback(full_campaign_id)
            if not archive_path or not archive_path.exists():
                raise web.HTTPServiceUnavailable(text="Archive generation failed.")

            return web.FileResponse(
                archive_path,
                headers={
                    "Content-Disposition": f'attachment; filename="{archive_path.name}"'
                },
            )
        except Exception as e:
            raise web.HTTPInternalServerError(text=f"Package generation failed: {e}")

    async def _admin_campaign_preview(self, request: web.Request) -> web.Response:
        """Dry-run campaign report submission (sends to operator's email)."""
        campaign_id = request.match_info.get("campaign_id", "")
        campaign = self._get_campaign_by_id(campaign_id)
        if not campaign:
            raise web.HTTPNotFound(text="Campaign not found.")

        await self._require_csrf(request)

        if not self.preview_campaign_report_callback:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/campaigns/{campaign_id}", msg="Preview not configured", error=1)
            )

        full_campaign_id = campaign.get("campaign_id", campaign_id)
        try:
            await self.preview_campaign_report_callback(full_campaign_id)
        except Exception as e:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/campaigns/{campaign_id}", msg=f"Preview failed: {e}", error=1)
            )

        raise web.HTTPSeeOther(
            location=_build_query_link(f"/admin/campaigns/{campaign_id}", msg="Preview sent to your email")
        )

    async def _admin_campaign_submit(self, request: web.Request) -> web.Response:
        """Submit campaign reports to all platforms."""
        campaign_id = request.match_info.get("campaign_id", "")
        campaign = self._get_campaign_by_id(campaign_id)
        if not campaign:
            raise web.HTTPNotFound(text="Campaign not found.")

        await self._require_csrf(request)

        if not self.submit_campaign_report_callback:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/campaigns/{campaign_id}", msg="Submit not configured", error=1)
            )

        full_campaign_id = campaign.get("campaign_id", campaign_id)
        try:
            await self.submit_campaign_report_callback(full_campaign_id)
        except Exception as e:
            raise web.HTTPSeeOther(
                location=_build_query_link(f"/admin/campaigns/{campaign_id}", msg=f"Submit failed: {e}", error=1)
            )

        raise web.HTTPSeeOther(
            location=_build_query_link(f"/admin/campaigns/{campaign_id}", msg="Reports submitted to all platforms")
        )
