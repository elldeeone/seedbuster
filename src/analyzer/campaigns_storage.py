"""Threat campaign storage helpers."""

from __future__ import annotations

import json
import logging
from datetime import datetime

from .campaigns_models import ThreatCampaign

logger = logging.getLogger(__name__)


class CampaignStorageMixin:
    """Persistence and index helpers."""

    def _migrate_legacy_storage(self) -> None:
        legacy_dir = self.data_dir.parent / "clusters"
        if not self.data_dir.exists() and legacy_dir.exists():
            try:
                legacy_dir.rename(self.data_dir)
            except Exception as exc:
                logger.warning("Failed to rename clusters directory to campaigns: %s", exc)

        legacy_file = self.data_dir / "clusters.json"
        campaigns_file = self.data_dir / "campaigns.json"
        if campaigns_file.exists() or not legacy_file.exists():
            return

        try:
            data = json.loads(legacy_file.read_text(encoding="utf-8"))
            entries = data.get("campaigns") or data.get("clusters") or []
            campaigns: list[dict] = []
            for entry in entries:
                payload = dict(entry or {})
                if "campaign_id" not in payload and "cluster_id" in payload:
                    payload["campaign_id"] = payload.pop("cluster_id")
                campaigns.append(payload)
            migrated = {
                "version": data.get("version", "1.0"),
                "saved_at": data.get("saved_at") or datetime.now().isoformat(),
                "campaigns": campaigns,
            }
            campaigns_file.write_text(json.dumps(migrated, indent=2), encoding="utf-8")
            legacy_file.unlink()
            logger.info("Migrated clusters.json to campaigns.json")
        except Exception as exc:
            logger.warning("Failed to migrate clusters.json to campaigns.json: %s", exc)

    def _load_campaigns(self) -> None:
        """Load campaigns from disk."""
        if self.campaigns_file.exists():
            try:
                with open(self.campaigns_file, "r") as f:
                    data = json.load(f)

                deduped = False
                for campaign_data in data.get("campaigns", []):
                    campaign = ThreatCampaign.from_dict(campaign_data)
                    if self._dedupe_campaign_members(campaign):
                        deduped = True
                    self.campaigns[campaign.campaign_id] = campaign
                    self._index_campaign(campaign)

                if deduped:
                    self._save_campaigns()
                    logger.info("Deduped campaign members on load")

                logger.info("Loaded %s threat campaigns", len(self.campaigns))
            except Exception as exc:
                logger.error("Failed to load campaigns: %s", exc)

    def _save_campaigns(self) -> None:
        """Save campaigns to disk."""
        self.data_dir.mkdir(parents=True, exist_ok=True)

        data = {
            "version": "1.0",
            "saved_at": datetime.now().isoformat(),
            "campaigns": [c.to_dict() for c in self.campaigns.values()],
        }

        with open(self.campaigns_file, "w") as f:
            json.dump(data, f, indent=2)

    def _index_campaign(self, campaign: ThreatCampaign) -> None:
        """Add campaign to lookup indices."""
        for backend in campaign.shared_backends:
            if backend not in self._backend_index:
                self._backend_index[backend] = set()
            self._backend_index[backend].add(campaign.campaign_id)

        for kit in campaign.shared_kits:
            if kit not in self._kit_index:
                self._kit_index[kit] = set()
            self._kit_index[kit].add(campaign.campaign_id)

        for ns in campaign.shared_nameservers:
            if ns not in self._ns_index:
                self._ns_index[ns] = set()
            self._ns_index[ns].add(campaign.campaign_id)

        for asn in campaign.shared_asns:
            if asn not in self._asn_index:
                self._asn_index[asn] = set()
            self._asn_index[asn].add(campaign.campaign_id)

        for member in campaign.members:
            domain_key = self._normalize_domain_key(member.domain)
            if domain_key:
                self._domain_index[domain_key] = campaign.campaign_id

    def _rebuild_indexes(self) -> None:
        self._backend_index = {}
        self._kit_index = {}
        self._ns_index = {}
        self._asn_index = {}
        self._domain_index = {}

        for campaign in self.campaigns.values():
            self._index_campaign(campaign)
