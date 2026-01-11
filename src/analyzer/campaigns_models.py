"""Threat campaign data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Set, List


@dataclass
class CampaignMember:
    """A domain that belongs to a threat campaign."""

    domain: str
    added_at: datetime
    score: int
    backends: List[str] = field(default_factory=list)
    kit_matches: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    ip_address: Optional[str] = None
    asn: Optional[str] = None
    html_hash: Optional[str] = None
    visual_hash: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "added_at": self.added_at.isoformat(),
            "score": self.score,
            "backends": self.backends,
            "kit_matches": self.kit_matches,
            "nameservers": self.nameservers,
            "ip_address": self.ip_address,
            "asn": self.asn,
            "html_hash": self.html_hash,
            "visual_hash": self.visual_hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CampaignMember":
        return cls(
            domain=data["domain"],
            added_at=datetime.fromisoformat(data["added_at"]),
            score=data["score"],
            backends=data.get("backends", []),
            kit_matches=data.get("kit_matches", []),
            nameservers=data.get("nameservers", []),
            ip_address=data.get("ip_address"),
            asn=data.get("asn"),
            html_hash=data.get("html_hash"),
            visual_hash=data.get("visual_hash"),
        )


@dataclass
class ThreatCampaign:
    """A campaign of related phishing sites."""

    campaign_id: str
    name: str
    created_at: datetime
    updated_at: datetime
    members: List[CampaignMember] = field(default_factory=list)

    # Shared indicators that define this campaign
    shared_backends: Set[str] = field(default_factory=set)
    shared_nameservers: Set[str] = field(default_factory=set)
    shared_kits: Set[str] = field(default_factory=set)
    shared_asns: Set[str] = field(default_factory=set)
    shared_visual_hashes: Set[str] = field(default_factory=set)

    # Threat actor attribution (optional)
    actor_id: Optional[str] = None
    actor_notes: str = ""

    # Confidence in campaign validity
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "members": [m.to_dict() for m in self.members],
            "shared_backends": list(self.shared_backends),
            "shared_nameservers": list(self.shared_nameservers),
            "shared_kits": list(self.shared_kits),
            "shared_asns": list(self.shared_asns),
            "shared_visual_hashes": list(self.shared_visual_hashes),
            "actor_id": self.actor_id,
            "actor_notes": self.actor_notes,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ThreatCampaign":
        campaign_id = data.get("campaign_id") or data.get("cluster_id")
        if not campaign_id:
            raise KeyError("campaign_id")
        campaign = cls(
            campaign_id=campaign_id,
            name=data["name"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            actor_id=data.get("actor_id"),
            actor_notes=data.get("actor_notes", ""),
            confidence=data.get("confidence", 0.0),
        )
        campaign.members = [CampaignMember.from_dict(m) for m in data.get("members", [])]
        campaign.shared_backends = set(data.get("shared_backends", []))
        campaign.shared_nameservers = set(data.get("shared_nameservers", []))
        campaign.shared_kits = set(data.get("shared_kits", []))
        campaign.shared_asns = set(data.get("shared_asns", []))
        campaign.shared_visual_hashes = set(data.get("shared_visual_hashes", []))
        return campaign


@dataclass
class CampaignMatch:
    """Result of trying to match a domain to existing campaigns."""

    campaign: Optional[ThreatCampaign]
    match_reasons: List[str]
    match_score: float
    is_new_campaign: bool = False
