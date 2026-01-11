"""Admin campaign API handlers."""

from __future__ import annotations

import json
from datetime import datetime

from aiohttp import web

from .server_helpers import _domain_similarity_pairs


class DashboardServerAdminApiCampaignsMixin:
    """Admin campaign API."""

    async def _admin_api_campaigns(self, request: web.Request) -> web.Response:
        campaigns = await self._filter_campaigns(self._load_campaigns())
        return web.json_response({"campaigns": campaigns})

    async def _admin_api_campaign(self, request: web.Request) -> web.Response:
        campaign_id = (request.match_info.get("campaign_id") or "").strip()
        if not campaign_id:
            raise web.HTTPBadRequest(text="campaign_id required")
        campaigns = await self._filter_campaigns(self._load_campaigns())
        campaign = next((c for c in campaigns if str(c.get("campaign_id")) == campaign_id), None)
        if not campaign:
            raise web.HTTPNotFound(text="Campaign not found")
        enriched = await self._enrich_related_domains_with_ids(campaign.get("members", []))
        campaign_payload = dict(campaign)
        campaign_payload["members"] = enriched
        pairs = _domain_similarity_pairs(campaign_payload.get("members", []))
        if pairs:
            campaign_payload["shared_domain_similarity"] = pairs
        return web.json_response({"campaign": campaign_payload, "domains": enriched})

    async def _admin_api_update_campaign_name(self, request: web.Request) -> web.Response:
        """Update campaign name (PATCH /admin/api/campaigns/{campaign_id}/name)."""
        self._require_csrf_header(request)
        campaign_id = (request.match_info.get("campaign_id") or "").strip()
        if not campaign_id:
            raise web.HTTPBadRequest(text="campaign_id required")

        data = await self._read_json(request)
        new_name = (data.get("name") or "").strip()
        if not new_name:
            return web.json_response({"error": "Name cannot be empty"}, status=400)

        if not self.campaigns_dir:
            return web.json_response({"error": "Campaigns not configured"}, status=500)

        campaigns_file = self.campaigns_dir / "campaigns.json"
        if not campaigns_file.exists():
            raise web.HTTPNotFound(text="Campaign file not found")

        try:
            with open(campaigns_file, "r") as f:
                data_file = json.load(f)

            campaigns = data_file.get("campaigns", [])
            found = False
            for campaign in campaigns:
                if str(campaign.get("campaign_id")) == campaign_id or str(campaign.get("campaign_id", "")).startswith(campaign_id):
                    campaign["name"] = new_name
                    campaign["updated_at"] = datetime.now().isoformat()
                    found = True
                    break

            if not found:
                raise web.HTTPNotFound(text="Campaign not found")

            data_file["saved_at"] = datetime.now().isoformat()
            with open(campaigns_file, "w") as f:
                json.dump(data_file, f, indent=2)

            return web.json_response({"status": "ok", "name": new_name})
        except web.HTTPNotFound:
            raise
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
