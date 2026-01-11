"""Threat campaign matching helpers."""

from __future__ import annotations

import difflib
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from ..utils.domain_similarity import domain_similarity_key_from_host
from .campaigns_models import CampaignMatch, CampaignMember, ThreatCampaign

logger = logging.getLogger(__name__)


class CampaignMatchingMixin:
    """Matching helpers."""

    def _normalize_domain_key(self, domain: str) -> str:
        raw = (domain or "").strip().lower()
        if not raw:
            return ""
        try:
            parsed = urlparse(raw if "://" in raw else f"http://{raw}")
            host = (parsed.hostname or raw.split("/")[0]).strip(".").lower()
            if host.startswith("www.") and len(host) > 4:
                host = host[4:]
            return host
        except Exception:
            return raw.split("/")[0].strip().lower()

    def _domain_similarity_key(self, domain: str) -> str:
        host = self._normalize_domain_key(domain)
        if not host:
            return ""
        return domain_similarity_key_from_host(host)

    def _best_domain_similarity(
        self,
        domain_label: str,
        campaign: ThreatCampaign,
    ) -> Tuple[float, Optional[str]]:
        best_ratio = 0.0
        best_domain = None
        for member in campaign.members:
            other_label = self._domain_similarity_key(member.domain)
            if not other_label:
                continue
            if min(len(domain_label), len(other_label)) < self.DOMAIN_SIMILARITY_MIN_LEN:
                continue
            ratio = difflib.SequenceMatcher(None, domain_label, other_label).ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_domain = member.domain
        return best_ratio, best_domain

    def _generate_campaign_id(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:6]
        return f"campaign_{timestamp}_{random_suffix}"

    def _generate_campaign_name(self, backends: List[str], kits: List[str]) -> str:
        if kits:
            kit_name = kits[0].replace("_", " ").title()
            return f"{kit_name} Campaign"

        if backends:
            backend = backends[0]
            parsed = urlparse(backend) if backend.startswith("http") else None
            if parsed and parsed.netloc:
                host = parsed.netloc.split(".")[0]
                return f"{host.title()} Backend Campaign"

        return f"Unknown Campaign {datetime.now().strftime('%Y%m%d')}"

    def _extract_backend_domain(self, url: str) -> Optional[str]:
        try:
            if url.startswith("http"):
                parsed = urlparse(url)
                return parsed.netloc.lower()
            return url.lower()
        except Exception:
            return None

    def _phash_distance(self, left: str, right: str) -> Optional[int]:
        if not left or not right:
            return None
        try:
            left_int = int(left, 16)
            right_int = int(right, 16)
        except ValueError:
            return None
        return (left_int ^ right_int).bit_count()

    def find_matching_campaign(
        self,
        domain: str,
        backends: List[str],
        kit_matches: List[str],
        nameservers: List[str],
        asn: Optional[str] = None,
        html_hash: Optional[str] = None,
        visual_hash: Optional[str] = None,
    ) -> CampaignMatch:
        """Find if domain matches an existing campaign."""
        domain_key = self._normalize_domain_key(domain)
        if domain_key and domain_key in self._domain_index:
            campaign_id = self._domain_index[domain_key]
            campaign = self.campaigns.get(campaign_id)
            if campaign:
                return CampaignMatch(
                    campaign=campaign,
                    match_reasons=[f"Same domain: {domain_key}"],
                    match_score=100.0,
                )

        candidate_scores: Dict[str, float] = {}
        match_reasons: Dict[str, List[str]] = {}
        indicator_types: Dict[str, Set[str]] = {}
        visual_campaigns: Set[str] = set()
        visual_loose_candidates: Dict[str, int] = {}

        generic_kits = {
            "metamask_phish",
            "trust_wallet_phish",
            "ledger_phish",
            "coinbase_phish",
            "generic_wallet_phish",
            "seed_phrase_stealer",
        }

        for backend in backends:
            backend_domain = self._extract_backend_domain(backend)
            if backend_domain and backend_domain in self._backend_index:
                for campaign_id in self._backend_index[backend_domain]:
                    if campaign_id not in candidate_scores:
                        candidate_scores[campaign_id] = 0
                        match_reasons[campaign_id] = []
                        indicator_types[campaign_id] = set()
                    candidate_scores[campaign_id] += 50
                    match_reasons[campaign_id].append(f"Shared backend: {backend_domain}")
                    indicator_types[campaign_id].add("backend")

        for kit in kit_matches:
            if kit in self._kit_index:
                is_generic = kit in generic_kits
                points = 15 if is_generic else 40
                for campaign_id in self._kit_index[kit]:
                    if campaign_id not in candidate_scores:
                        candidate_scores[campaign_id] = 0
                        match_reasons[campaign_id] = []
                        indicator_types[campaign_id] = set()
                    candidate_scores[campaign_id] += points
                    kit_type = "generic kit" if is_generic else "specific kit"
                    match_reasons[campaign_id].append(f"Same {kit_type}: {kit}")
                    indicator_types[campaign_id].add("kit_generic" if is_generic else "kit")

        privacy_ns_patterns = ["njalla", "1984", "orangewebsite"]
        for ns in nameservers:
            ns_lower = ns.lower()
            is_privacy = any(p in ns_lower for p in privacy_ns_patterns)
            points = 30 if is_privacy else 10

            if ns_lower in self._ns_index:
                for campaign_id in self._ns_index[ns_lower]:
                    if campaign_id not in candidate_scores:
                        candidate_scores[campaign_id] = 0
                        match_reasons[campaign_id] = []
                        indicator_types[campaign_id] = set()
                    candidate_scores[campaign_id] += points
                    ns_type = "privacy DNS" if is_privacy else "nameserver"
                    match_reasons[campaign_id].append(f"Shared {ns_type}: {ns}")
                    indicator_types[campaign_id].add("dns_privacy" if is_privacy else "dns")

        if asn and asn in self._asn_index:
            for campaign_id in self._asn_index[asn]:
                if campaign_id not in candidate_scores:
                    candidate_scores[campaign_id] = 0
                    match_reasons[campaign_id] = []
                    indicator_types[campaign_id] = set()
                candidate_scores[campaign_id] += 20
                match_reasons[campaign_id].append(f"Same ASN: {asn}")
                indicator_types[campaign_id].add("asn")

        if visual_hash:
            for campaign_id, campaign in self.campaigns.items():
                if not campaign.shared_visual_hashes:
                    continue
                best_distance = None
                for candidate_hash in campaign.shared_visual_hashes:
                    distance = self._phash_distance(visual_hash, candidate_hash)
                    if distance is None:
                        continue
                    if best_distance is None or distance < best_distance:
                        best_distance = distance
                if best_distance is None:
                    continue
                if best_distance <= self.VISUAL_HASH_DISTANCE_STRICT:
                    visual_campaigns.add(campaign_id)
                elif best_distance <= self.VISUAL_HASH_DISTANCE_LOOSE:
                    visual_loose_candidates[campaign_id] = best_distance

        for campaign_id in visual_campaigns:
            if campaign_id not in candidate_scores:
                candidate_scores[campaign_id] = 0
                match_reasons[campaign_id] = []
                indicator_types[campaign_id] = set()
            candidate_scores[campaign_id] += self.VISUAL_MATCH_SCORE
            match_reasons[campaign_id].append("Visual match to campaign fingerprint")
            indicator_types[campaign_id].add("visual")

        if not visual_campaigns and visual_loose_candidates:
            for campaign_id, distance in visual_loose_candidates.items():
                if campaign_id not in candidate_scores:
                    candidate_scores[campaign_id] = 0
                    match_reasons[campaign_id] = []
                    indicator_types[campaign_id] = set()
                candidate_scores[campaign_id] += self.VISUAL_MATCH_SCORE_LOOSE
                match_reasons[campaign_id].append(
                    f"Loose visual match to campaign fingerprint (distance {distance})"
                )
                indicator_types[campaign_id].add("visual")

        domain_label = self._domain_similarity_key(domain)
        if domain_label:
            for campaign_id, campaign in self.campaigns.items():
                ratio, match_domain = self._best_domain_similarity(domain_label, campaign)
                if ratio >= self.DOMAIN_SIMILARITY_THRESHOLD:
                    if campaign_id not in candidate_scores:
                        candidate_scores[campaign_id] = 0
                        match_reasons[campaign_id] = []
                        indicator_types[campaign_id] = set()
                    candidate_scores[campaign_id] += self.DOMAIN_SIMILARITY_SCORE
                    match_reasons[campaign_id].append(
                        f"Similar domain: {domain} ~ {match_domain} ({ratio:.2f})"
                    )
                    indicator_types[campaign_id].add("domain")

        if not candidate_scores:
            return CampaignMatch(campaign=None, match_reasons=[], match_score=0)

        best_campaign_id = max(candidate_scores, key=candidate_scores.get)
        best_score = candidate_scores[best_campaign_id]
        types_matched = len(indicator_types.get(best_campaign_id, []))

        if types_matched >= 2:
            return CampaignMatch(
                campaign=self.campaigns[best_campaign_id],
                match_reasons=match_reasons[best_campaign_id],
                match_score=min(best_score, 100),
            )
        if best_score >= 50:
            logger.debug(
                "Rejected campaign match for %s: score=%s but only %s indicator type(s)",
                domain,
                best_score,
                types_matched,
            )

        return CampaignMatch(campaign=None, match_reasons=[], match_score=0)

    def add_to_campaign(
        self,
        domain: str,
        score: int,
        backends: List[str],
        kit_matches: List[str],
        nameservers: List[str],
        asn: Optional[str] = None,
        ip_address: Optional[str] = None,
        html_hash: Optional[str] = None,
        visual_hash: Optional[str] = None,
    ) -> Tuple[ThreatCampaign, bool]:
        """Add domain to appropriate campaign, creating new one if needed."""
        backend_domains = []
        for b in backends:
            bd = self._extract_backend_domain(b)
            if bd:
                backend_domains.append(bd)

        match = self.find_matching_campaign(
            domain=domain,
            backends=backend_domains,
            kit_matches=kit_matches,
            nameservers=[ns.lower() for ns in nameservers],
            asn=asn,
            html_hash=html_hash,
            visual_hash=visual_hash,
        )

        member = CampaignMember(
            domain=domain,
            added_at=datetime.now(),
            score=score,
            backends=backend_domains,
            kit_matches=kit_matches,
            nameservers=[ns.lower() for ns in nameservers],
            ip_address=ip_address,
            asn=asn,
            html_hash=html_hash,
            visual_hash=visual_hash,
        )

        if match.campaign and match.match_score >= 50:
            campaign = match.campaign
            domain_key = self._normalize_domain_key(domain)
            existing_member = None
            if domain_key:
                for existing in campaign.members:
                    if self._normalize_domain_key(existing.domain) == domain_key:
                        existing_member = existing
                        break

            changed = False
            if existing_member:
                changed = self._merge_member_into_existing(existing_member, member)
            else:
                campaign.members.append(member)
                changed = True

            shared_changed = False
            if changed:
                shared_changed = self._rebuild_campaign_shared_indicators(campaign)

            if changed or shared_changed:
                campaign.updated_at = datetime.now()
                campaign.confidence = self._calculate_campaign_confidence(campaign)
                self._rebuild_indexes()
                self._save_campaigns()

                action = "Merged" if existing_member else "Added"
                logger.info(
                    "%s %s in campaign '%s' (match: %.0f%%, reasons: %s)",
                    action,
                    domain,
                    campaign.name,
                    match.match_score,
                    match.match_reasons,
                )

            return campaign, False

        campaign_id = self._generate_campaign_id()
        campaign_name = self._generate_campaign_name(backend_domains, kit_matches)

        campaign = ThreatCampaign(
            campaign_id=campaign_id,
            name=campaign_name,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            members=[member],
            shared_backends=set(backend_domains),
            shared_kits=set(kit_matches),
            shared_nameservers=set(ns.lower() for ns in nameservers),
            shared_asns={asn} if asn else set(),
            shared_visual_hashes={visual_hash} if visual_hash else set(),
            confidence=50.0,
        )

        self.campaigns[campaign_id] = campaign
        self._index_campaign(campaign)
        self._save_campaigns()

        logger.info("Created new campaign '%s' for %s", campaign_name, domain)

        return campaign, True
