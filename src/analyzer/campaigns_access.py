"""Threat campaign access helpers."""

from __future__ import annotations

from typing import Dict, List, Optional

from .campaigns_models import ThreatCampaign


class CampaignAccessMixin:
    """Accessors and summary helpers."""

    def get_campaign_for_domain(self, domain: str) -> Optional[ThreatCampaign]:
        """Get campaign containing a domain."""
        domain_key = self._normalize_domain_key(domain)
        campaign_id = self._domain_index.get(domain_key)
        if campaign_id:
            return self.campaigns.get(campaign_id)
        return None

    def get_related_domains(self, domain: str) -> List[str]:
        """Get all domains related to a given domain via campaigns."""
        campaign = self.get_campaign_for_domain(domain)
        if campaign:
            current_key = self._normalize_domain_key(domain)
            return [
                m.domain
                for m in campaign.members
                if self._normalize_domain_key(m.domain) != current_key
            ]
        return []

    def get_campaign_summary(self, campaign_id: str) -> Optional[Dict]:
        """Get summary info for a specific campaign."""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return None

        return {
            "campaign_id": campaign.campaign_id,
            "name": campaign.name,
            "member_count": len(campaign.members),
            "shared_backends": list(campaign.shared_backends),
            "shared_kits": list(campaign.shared_kits),
            "shared_nameservers": list(campaign.shared_nameservers),
            "shared_asns": list(campaign.shared_asns),
            "confidence": campaign.confidence,
            "created_at": campaign.created_at.isoformat(),
            "updated_at": campaign.updated_at.isoformat(),
        }

    def get_all_campaigns(self) -> List[Dict]:
        """Get summary info for all campaigns."""
        campaigns = []
        for campaign in self.campaigns.values():
            campaigns.append(self.get_campaign_summary(campaign.campaign_id))

        campaigns.sort(key=lambda c: c["updated_at"], reverse=True)
        return campaigns

    def get_stats(self) -> Dict:
        """Get campaign statistics."""
        total_campaigns = len(self.campaigns)
        total_domains = sum(len(c.members) for c in self.campaigns.values())
        return {
            "total_campaigns": total_campaigns,
            "total_domains": total_domains,
            "avg_domains_per_campaign": total_domains / max(total_campaigns, 1),
        }

    def to_dict(self) -> dict:
        """Convert all campaigns to dict for serialization."""
        return {
            "campaigns": [c.to_dict() for c in self.campaigns.values()],
            "stats": self.get_stats(),
        }
