"""Public page handlers."""

from __future__ import annotations

from pathlib import Path

from aiohttp import web

from ..storage.database import DomainStatus
from .server_helpers import DANGEROUS_EXCLUDE_STATUSES, _coerce_int, _domain_dir_name
from .server_layout import _layout
from .server_render_campaigns import _render_campaign_detail, _render_campaigns_list
from .server_render_domain import _render_domain_detail
from .server_render_sections import _flash, _render_domains_section, _render_stats


class DashboardServerPublicPagesMixin:
    """Public HTML handlers."""

    async def _public_index(self, request: web.Request) -> web.Response:
        status_param_present = "status" in request.query
        status_raw = (request.query.get("status") or "").strip().lower()
        status = status_raw if status_param_present else "dangerous"
        verdict = (request.query.get("verdict") or "").strip().lower()
        q = (request.query.get("q") or "").strip().lower()
        exclude_takedowns_raw = (request.query.get("exclude_takedowns") or "").strip().lower()
        exclude_takedowns = exclude_takedowns_raw in {"1", "true", "yes"}
        if not exclude_takedowns_raw and not status_param_present:
            exclude_takedowns = True
        limit = _coerce_int(request.query.get("limit"), default=100, min_value=1, max_value=500)
        page = _coerce_int(request.query.get("page"), default=1, min_value=1, max_value=10_000)
        offset = (page - 1) * limit

        stats = await self._get_stats_cached()

        status_filter = None if status == "dangerous" else (status or None)
        exclude_statuses = DANGEROUS_EXCLUDE_STATUSES if status == "dangerous" else None

        total_count = await self.database.count_domains(
            status=status_filter,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
            exclude_takedowns=exclude_takedowns,
        )
        await self._fetch_health_status()
        domains = await self.database.list_domains(
            limit=limit,
            offset=offset,
            status=status_filter,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
            exclude_takedowns=exclude_takedowns,
        )

        body = (
            _flash(request.query.get("msg"))
            + _render_stats(stats, admin=False)
            + _render_domains_section(
                domains,
                admin=False,
                total=total_count,
                status=status,
                verdict=verdict,
                q=q,
                limit=limit,
                page=page,
                include_dangerous=True,
            )
        )
        html_out = _layout(title="SeedBuster Dashboard", body=body, admin=False)
        return web.Response(text=html_out, content_type="text/html")

    async def _public_domain(self, request: web.Request) -> web.Response:
        did = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        domain = await self.database.get_domain_by_id(did)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found.")

        is_allowlisted = (
            str(domain.get("status") or "").strip().lower() == DomainStatus.ALLOWLISTED.value
            or self._is_allowlisted_domain(domain["domain"])
        )
        reports = [] if is_allowlisted else await self.database.get_reports_for_domain(did)
        snapshot_param = (request.query.get("snapshot") or "").strip()
        domain_dir = self.evidence_dir / _domain_dir_name(domain["domain"])
        snapshots, latest_id = ([], None)
        snapshot_dir = None
        resolved_snapshot_id = None
        is_latest = True
        evidence_base = None
        evidence_cache_buster = None
        screenshots: list[Path] = []
        instruction_files: list[Path] = []
        if not is_allowlisted:
            _snapshots, latest_id = self._list_snapshots(domain_dir)
            snapshot_dir, resolved_snapshot_id, is_latest = self._resolve_snapshot_dir(
                domain_dir, snapshot_param, latest_id
            )
            if snapshot_param and not snapshot_dir and domain_dir.exists():
                snapshot_dir = domain_dir
                resolved_snapshot_id = latest_id
                is_latest = True

            evidence_cache_buster = resolved_snapshot_id or latest_id
            if snapshot_dir:
                evidence_base = f"/evidence/{domain_dir.name}"
                if not is_latest and resolved_snapshot_id:
                    evidence_base = f"/evidence/{domain_dir.name}/runs/{resolved_snapshot_id}"
            screenshots = self._get_screenshots(domain, snapshot_dir)
            instruction_files = self._get_instruction_files(domain_dir) if is_latest else []

        domain_name = domain.get("domain") or ""
        campaign = self._get_campaign_for_domain(domain_name)
        related_domains = self._get_related_domains(domain_name, campaign)
        related_domains = await self._enrich_related_domains_with_ids(related_domains)

        body = _render_domain_detail(
            domain,
            self._filter_reports_for_snapshot(reports, snapshots, resolved_snapshot_id or latest_id),
            evidence_dir=snapshot_dir,
            evidence_base_url=evidence_base,
            evidence_cache_buster=evidence_cache_buster,
            screenshots=screenshots,
            instruction_files=instruction_files,
            admin=False,
            csrf=None,
            msg=request.query.get("msg"),
            error=(request.query.get("error") == "1"),
            available_platforms=[],
            campaign=campaign,
            related_domains=related_domains,
        )
        html_out = _layout(title="SeedBuster Dashboard", body=body, admin=False)
        return web.Response(text=html_out, content_type="text/html")

    async def _public_campaigns(self, request: web.Request) -> web.Response:
        search = (request.query.get("q") or "").strip()
        campaigns = await self._filter_campaigns(self._load_campaigns())
        body = _render_campaigns_list(campaigns, admin=False, q=search)
        html_out = _layout(title="SeedBuster - Threat Campaigns", body=body, admin=False)
        return web.Response(text=html_out, content_type="text/html")

    async def _public_campaign_detail(self, request: web.Request) -> web.Response:
        campaign_id = (request.match_info.get("campaign_id") or "").strip()
        if not campaign_id:
            raise web.HTTPNotFound(text="Campaign not found.")

        campaigns = await self._filter_campaigns(self._load_campaigns())
        campaign = next(
            (
                c
                for c in campaigns
                if str(c.get("campaign_id")) == campaign_id
                or str(c.get("campaign_id", "")).startswith(campaign_id)
            ),
            None,
        )
        if not campaign:
            raise web.HTTPNotFound(text="Campaign not found.")

        enriched_members = await self._enrich_related_domains_with_ids(campaign.get("members", []))
        campaign = dict(campaign)
        campaign["members"] = enriched_members

        body = _render_campaign_detail(campaign, admin=False)
        html_out = _layout(
            title=f"Campaign: {campaign.get('name', 'Unknown Campaign')}",
            body=body,
            admin=False,
        )
        return web.Response(text=html_out, content_type="text/html")
