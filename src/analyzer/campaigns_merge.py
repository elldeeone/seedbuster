"""Threat campaign merge helpers."""

from __future__ import annotations

from typing import Dict, List, Set
from urllib.parse import urlparse

from .campaigns_models import CampaignMember, ThreatCampaign


class CampaignMergeMixin:
    """Merge/dedupe helpers."""

    def _domain_preference(self, domain: str) -> tuple[int, int, int, int]:
        raw = (domain or "").strip().lower()
        if not raw:
            return (1, 1, 1, 0)
        has_scheme = "://" in raw
        try:
            parsed = urlparse(raw if has_scheme else f"http://{raw}")
            host = (parsed.hostname or raw.split("/")[0]).strip(".").lower()
            has_path = bool(parsed.path and parsed.path != "/")
        except Exception:
            host = raw.split("/")[0].strip(".").lower()
            has_path = "/" in raw
        is_www = host.startswith("www.")
        return (1 if has_scheme else 0, 1 if has_path else 0, 1 if is_www else 0, len(raw))

    @staticmethod
    def _merge_unique_lists(values: List[List[str]]) -> List[str]:
        merged: List[str] = []
        seen = set()
        for items in values:
            for item in items or []:
                if item not in seen:
                    seen.add(item)
                    merged.append(item)
        return merged

    def _merge_campaign_members(self, members: List[CampaignMember]) -> CampaignMember:
        if len(members) == 1:
            return members[0]
        base = min(members, key=lambda m: self._domain_preference(m.domain))
        base.domain = min(
            (m.domain for m in members if m.domain),
            key=self._domain_preference,
            default=base.domain,
        )
        base.added_at = min(
            (m.added_at for m in members if m.added_at),
            default=base.added_at,
        )
        base.score = max(
            (m.score for m in members if m.score is not None),
            default=base.score,
        )
        base.backends = self._merge_unique_lists([m.backends for m in members])
        base.kit_matches = self._merge_unique_lists([m.kit_matches for m in members])
        base.nameservers = self._merge_unique_lists([m.nameservers for m in members])
        for attr in ("ip_address", "asn", "html_hash", "visual_hash"):
            if getattr(base, attr):
                continue
            for member in members:
                value = getattr(member, attr)
                if value:
                    setattr(base, attr, value)
                    break
        return base

    def _merge_member_into_existing(
        self,
        target: CampaignMember,
        incoming: CampaignMember,
    ) -> bool:
        changed = False
        preferred = min(
            [target.domain, incoming.domain],
            key=self._domain_preference,
        )
        if preferred and preferred != target.domain:
            target.domain = preferred
            changed = True

        earliest = min(
            (m.added_at for m in (target, incoming) if m.added_at),
            default=target.added_at,
        )
        if earliest != target.added_at:
            target.added_at = earliest
            changed = True

        if incoming.score is not None and incoming.score > target.score:
            target.score = incoming.score
            changed = True

        if incoming.backends:
            merged_backends = self._merge_unique_lists([incoming.backends])
            if merged_backends != target.backends:
                target.backends = merged_backends
                changed = True

        if incoming.kit_matches:
            merged_kits = self._merge_unique_lists([incoming.kit_matches])
            if merged_kits != target.kit_matches:
                target.kit_matches = merged_kits
                changed = True

        if incoming.nameservers:
            merged_nameservers = self._merge_unique_lists([incoming.nameservers])
            if merged_nameservers != target.nameservers:
                target.nameservers = merged_nameservers
                changed = True

        for attr in ("ip_address", "asn", "html_hash", "visual_hash"):
            value = getattr(incoming, attr)
            if value and value != getattr(target, attr):
                setattr(target, attr, value)
                changed = True

        return changed

    def _rebuild_campaign_shared_indicators(self, campaign: ThreatCampaign) -> bool:
        backends: Set[str] = set()
        kits: Set[str] = set()
        nameservers: Set[str] = set()
        asns: Set[str] = set()
        visual_hashes: Set[str] = set()

        for member in campaign.members:
            backends.update(member.backends or [])
            kits.update(member.kit_matches or [])
            nameservers.update(ns.lower() for ns in (member.nameservers or []))
            if member.asn:
                asns.add(member.asn)
            if member.visual_hash:
                visual_hashes.add(member.visual_hash)

        changed = (
            backends != campaign.shared_backends
            or kits != campaign.shared_kits
            or nameservers != campaign.shared_nameservers
            or asns != campaign.shared_asns
            or visual_hashes != campaign.shared_visual_hashes
        )

        campaign.shared_backends = backends
        campaign.shared_kits = kits
        campaign.shared_nameservers = nameservers
        campaign.shared_asns = asns
        campaign.shared_visual_hashes = visual_hashes
        return changed

    def _dedupe_campaign_members(self, campaign: ThreatCampaign) -> bool:
        if len(campaign.members) <= 1:
            return False
        grouped: Dict[str, List[CampaignMember]] = {}
        order: List[str] = []
        for member in campaign.members:
            key = self._normalize_domain_key(member.domain) or (
                (member.domain or "").strip().lower()
            )
            if key not in grouped:
                grouped[key] = []
                order.append(key)
            grouped[key].append(member)
        if all(len(items) == 1 for items in grouped.values()):
            return False
        campaign.members = [
            self._merge_campaign_members(grouped[key]) for key in order
        ]
        return True

    def _calculate_campaign_confidence(self, campaign: ThreatCampaign) -> float:
        """Calculate confidence score for a campaign."""
        score = 0.0

        member_count = len(campaign.members)
        score += min(member_count * 10, 30)

        if campaign.shared_backends:
            score += min(len(campaign.shared_backends) * 20, 40)

        if campaign.shared_kits:
            score += min(len(campaign.shared_kits) * 10, 20)

        if campaign.shared_nameservers:
            privacy_count = sum(
                1
                for ns in campaign.shared_nameservers
                if any(p in ns for p in ["njalla", "1984", "orangewebsite"])
            )
            score += min(privacy_count * 5 + len(campaign.shared_nameservers) * 2, 10)

        return min(score, 100)
