"""Admin campaign detail page handlers."""

from __future__ import annotations

from aiohttp import web

from .server_layout import _layout
from .server_render_campaigns import _render_campaign_detail
from .server_render_sections import _flash


class DashboardServerAdminCampaignDetailMixin:
    """Admin campaign detail pages."""

    async def _admin_campaign_detail(self, request: web.Request) -> web.Response:
        """Show detailed threat campaign view with action buttons."""
        campaign_id = request.match_info.get("campaign_id", "")
        campaigns = await self._filter_campaigns(self._load_campaigns())
        campaign = next(
            (
                c for c in campaigns
                if str(c.get("campaign_id")) == campaign_id or str(c.get("campaign_id", "")).startswith(campaign_id)
            ),
            None,
        )
        if not campaign:
            raise web.HTTPNotFound(text="Campaign not found.")

        enriched_members = await self._enrich_related_domains_with_ids(campaign.get("members", []))
        campaign = dict(campaign)
        campaign["members"] = enriched_members

        msg = request.query.get("msg")
        error = request.query.get("error") == "1"

        body = _render_campaign_detail(campaign, admin=True)
        html_out = _layout(
            title=f"Campaign: {campaign.get('name', 'Unknown')}",
            body=_flash(msg, error=error) + body,
            admin=True,
        )

        resp = web.Response(text=html_out, content_type="text/html")
        csrf = self._get_or_set_csrf(request, resp)
        resp.text = resp.text.replace("__SET_COOKIE__", csrf)
        return resp
