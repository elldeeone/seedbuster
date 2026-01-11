"""
Layer 5: Threat Campaigns

Links related phishing sites together by analyzing:
- Shared backend infrastructure (C2 endpoints)
- Common hosting/DNS patterns
- HTML/JS content similarity
- Kit signature matches

Enables tracking of threat actor campaigns over time.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .campaigns_manager import ThreatCampaignManager
from .campaigns_models import CampaignMatch, CampaignMember, ThreatCampaign

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CampaignAnalysisResult:
    """Summary of campaign analysis for a domain."""

    campaign_id: str | None = None
    campaign_name: str | None = None
    is_new_campaign: bool = False
    related_domains: list[str] = field(default_factory=list)
    confidence: float | None = None


def analyze_for_campaign(
    *,
    manager: ThreatCampaignManager | None,
    domain: str,
    detection_result: dict[str, Any] | None = None,
    infrastructure: dict[str, Any] | None = None,
) -> CampaignAnalysisResult:
    """Add domain to a campaign and return a summary for downstream use."""
    result = CampaignAnalysisResult()
    if not manager:
        return result

    detection_result = detection_result or {}
    infrastructure = infrastructure or {}

    score = int(detection_result.get("score") or 0)
    backends = [b for b in (detection_result.get("suspicious_endpoints") or []) if isinstance(b, str)]
    kit_matches = [k for k in (detection_result.get("kit_matches") or []) if isinstance(k, str)]
    visual_hash = detection_result.get("visual_hash") or None
    nameservers = [ns for ns in (infrastructure.get("nameservers") or []) if isinstance(ns, str)]
    asn = infrastructure.get("asn") or None
    ip_address = infrastructure.get("ip") or None

    try:
        campaign, is_new = manager.add_to_campaign(
            domain=domain,
            score=score,
            backends=backends,
            kit_matches=kit_matches,
            nameservers=nameservers,
            asn=asn,
            ip_address=ip_address,
            html_hash=None,
            visual_hash=visual_hash,
        )
    except Exception as exc:
        logger.exception("Campaign analysis failed for %s: %s", domain, exc)
        return result

    result.campaign_id = getattr(campaign, "campaign_id", None)
    result.campaign_name = getattr(campaign, "name", None)
    result.is_new_campaign = bool(is_new)
    result.confidence = getattr(campaign, "confidence", None)
    try:
        result.related_domains = manager.get_related_domains(domain) or []
    except Exception:
        members = getattr(campaign, "members", []) or []
        result.related_domains = [
            member.domain for member in members if getattr(member, "domain", None) and member.domain != domain
        ]
    return result

__all__ = [
    "CampaignMember",
    "ThreatCampaign",
    "CampaignMatch",
    "ThreatCampaignManager",
    "CampaignAnalysisResult",
    "analyze_for_campaign",
]
