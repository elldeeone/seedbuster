"""Campaign helpers for dashboard server."""

from __future__ import annotations

import json

from ..storage.database import DomainStatus
from .server_helpers import _domain_similarity_pairs


class DashboardServerCampaignsMixin:
    """Campaign lookup helpers."""

    def _load_campaigns(self) -> list[dict]:
        """Load all threat campaigns from campaigns.json."""
        if not self.campaigns_dir:
            return []
        campaigns_file = self.campaigns_dir / "campaigns.json"
        if not campaigns_file.exists():
            return []
        try:
            with open(campaigns_file, "r") as f:
                data = json.load(f)
            return data.get("campaigns", [])
        except Exception:
            return []

    async def _filter_campaigns(self, campaigns: list[dict]) -> list[dict]:
        """Hide campaigns whose members are all allowlisted/watchlist/false positive."""
        if not campaigns:
            return []

        member_domains: set[str] = set()
        for campaign in campaigns:
            for member in campaign.get("members", []):
                name = (member.get("domain") or "").strip().lower()
                if name:
                    member_domains.add(name)
                    normalized = self._normalize_domain_key(name)
                    if normalized:
                        member_domains.add(normalized)

        domain_records = await self.database.get_domains_by_names(list(member_domains))
        excluded_statuses = {
            DomainStatus.ALLOWLISTED.value,
            DomainStatus.FALSE_POSITIVE.value,
            DomainStatus.WATCHLIST.value,
        }

        seen_normalized: set[str] = set()
        filtered: list[dict] = []
        for campaign in campaigns:
            kept_members: list[dict] = []
            new_keys: set[str] = set()
            for member in campaign.get("members", []):
                domain_name = (member.get("domain") or "").strip()
                if not domain_name:
                    continue

                normalized_key = self._normalize_domain_key(domain_name)
                record = domain_records.get(domain_name.lower()) or domain_records.get(normalized_key)
                status = (record.get("status") if record else "") or ""
                verdict = (record.get("verdict") if record else "") or ""

                if self._is_allowlisted_domain(domain_name):
                    status = DomainStatus.ALLOWLISTED.value

                if status in excluded_statuses:
                    continue

                if normalized_key and normalized_key in seen_normalized:
                    continue

                enriched = dict(member)
                if record:
                    enriched.update(record)
                if status:
                    enriched["status"] = status
                if verdict and not enriched.get("verdict"):
                    enriched["verdict"] = verdict
                kept_members.append(enriched)
                if normalized_key:
                    new_keys.add(normalized_key)

            if kept_members:
                seen_normalized.update(new_keys)
                new_campaign = dict(campaign)
                new_campaign["members"] = kept_members
                filtered.append(new_campaign)

        return filtered

    def _get_campaign_for_domain(self, domain: str) -> dict | None:
        """Get campaign info for a specific domain."""
        if self._is_allowlisted_domain(domain):
            return None
        campaigns = self._load_campaigns()
        for campaign in campaigns:
            members = campaign.get("members", [])
            for member in members:
                if member.get("domain") == domain:
                    payload = dict(campaign)
                    pairs = _domain_similarity_pairs(payload.get("members", []))
                    if pairs:
                        payload["shared_domain_similarity"] = pairs
                    return payload
        return None

    def _get_related_domains(self, domain: str, campaign: dict | None) -> list[dict]:
        """Get list of related domains from the same campaign."""
        if not campaign:
            return []
        members = campaign.get("members", [])
        current_key = self._normalize_domain_key(domain)
        return [m for m in members if self._normalize_domain_key(m.get("domain")) != current_key]

    async def _enrich_related_domains_with_ids(self, related_domains: list[dict]) -> list[dict]:
        """Look up domain IDs from database and add them to related_domains."""
        enriched = []
        for member in related_domains:
            domain_name = member.get("domain", "")
            domain_record = await self.database.get_domain(domain_name)
            enriched_member = dict(member)
            if domain_record:
                enriched_member["id"] = domain_record.get("id")
            enriched.append(enriched_member)
        return enriched

    def _get_campaign_by_id(self, campaign_id: str) -> dict | None:
        """Get a specific campaign by ID (supports prefix matching)."""
        campaigns = self._load_campaigns()
        for campaign in campaigns:
            cid = campaign.get("campaign_id", "")
            if cid == campaign_id or cid.startswith(campaign_id):
                return campaign
        return None
