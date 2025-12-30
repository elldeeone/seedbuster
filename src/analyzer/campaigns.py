"""
Layer 5: Threat Campaigns

Links related phishing sites together by analyzing:
- Shared backend infrastructure (C2 endpoints)
- Common hosting/DNS patterns
- HTML/JS content similarity
- Kit signature matches

Enables tracking of threat actor campaigns over time.
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


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
    name: str  # Human-readable name like "kaspa_stealer_campaign_1"
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
    match_score: float  # 0-100
    is_new_campaign: bool = False


class ThreatCampaignManager:
    """
    Manages threat campaigns - groups of related phishing sites.

    Campaign grouping is based on:
    1. Shared backend infrastructure (highest weight)
    2. Same phishing kit signatures
    3. Common nameservers (especially privacy DNS)
    4. Same ASN/hosting provider
    5. HTML content similarity
    """


    VISUAL_HASH_DISTANCE = 4
    VISUAL_MATCH_SCORE = 40

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._migrate_legacy_storage()
        self.campaigns_file = data_dir / "campaigns.json"
        self.campaigns: Dict[str, ThreatCampaign] = {}

        # Index for fast lookups
        self._backend_index: Dict[str, Set[str]] = {}  # backend -> campaign_ids
        self._kit_index: Dict[str, Set[str]] = {}  # kit -> campaign_ids
        self._ns_index: Dict[str, Set[str]] = {}  # nameserver -> campaign_ids
        self._asn_index: Dict[str, Set[str]] = {}  # asn -> campaign_ids
        self._domain_index: Dict[str, str] = {}  # domain -> campaign_id

        self._load_campaigns()

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

    def _normalize_domain_key(self, domain: str) -> str:
        """Normalize domains for campaign comparisons (strip scheme/path, lowercase)."""
        raw = (domain or "").strip().lower()
        if not raw:
            return ""
        try:
            parsed = urlparse(raw if "://" in raw else f"http://{raw}")
            host = (parsed.hostname or raw.split("/")[0]).strip(".").lower()
            return host
        except Exception:
            return raw.split("/")[0].strip().lower()

    def _load_campaigns(self):
        """Load campaigns from disk."""
        if self.campaigns_file.exists():
            try:
                with open(self.campaigns_file, "r") as f:
                    data = json.load(f)

                for campaign_data in data.get("campaigns", []):
                    campaign = ThreatCampaign.from_dict(campaign_data)
                    self.campaigns[campaign.campaign_id] = campaign
                    self._index_campaign(campaign)

                logger.info(f"Loaded {len(self.campaigns)} threat campaigns")
            except Exception as e:
                logger.error(f"Failed to load campaigns: {e}")

    def _save_campaigns(self):
        """Save campaigns to disk."""
        self.data_dir.mkdir(parents=True, exist_ok=True)

        data = {
            "version": "1.0",
            "saved_at": datetime.now().isoformat(),
            "campaigns": [c.to_dict() for c in self.campaigns.values()],
        }

        with open(self.campaigns_file, "w") as f:
            json.dump(data, f, indent=2)

    def _index_campaign(self, campaign: ThreatCampaign):
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

    def _generate_campaign_id(self) -> str:
        """Generate unique campaign ID."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:6]
        return f"campaign_{timestamp}_{random_suffix}"

    def _generate_campaign_name(self, backends: List[str], kits: List[str]) -> str:
        """Generate human-readable campaign name."""
        if kits:
            kit_name = kits[0].replace("_", " ").title()
            return f"{kit_name} Campaign"

        if backends:
            # Extract meaningful part from backend URL
            backend = backends[0]
            parsed = urlparse(backend) if backend.startswith("http") else None
            if parsed and parsed.netloc:
                host = parsed.netloc.split(".")[0]
                return f"{host.title()} Backend Campaign"

        return f"Unknown Campaign {datetime.now().strftime('%Y%m%d')}"

    def _extract_backend_domain(self, url: str) -> Optional[str]:
        """Extract domain from backend URL for comparison."""
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
        """
        Find if domain matches an existing campaign.

        Returns CampaignMatch with:
        - campaign: Matching campaign or None
        - match_reasons: Why it matched
        - match_score: Confidence of match (0-100)
        """
        # Check if domain (normalized) already belongs to a campaign
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

        # Score matches against each indicator type
        candidate_scores: Dict[str, float] = {}  # campaign_id -> score
        match_reasons: Dict[str, List[str]] = {}  # campaign_id -> reasons
        # Track which indicator TYPES matched for each campaign (require multiple)
        indicator_types: Dict[str, Set[str]] = {}  # campaign_id -> set of types

        # Generic kits are common across many phishing sites and shouldn't
        # be strong enough alone to link domains to a campaign
        generic_kits = {
            "metamask_phish", "trust_wallet_phish", "ledger_phish",
            "coinbase_phish", "generic_wallet_phish", "seed_phrase_stealer",
        }

        # Backend matching (highest weight: 50 points)
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

        # Kit signature matching (points depend on kit specificity)
        # Specific kits (kaspa_stealer_v1, etc): 40 points
        # Generic kits (metamask_phish, etc): 15 points (alone not enough to match)
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
                    indicator_types[campaign_id].add("kit")

        # Nameserver matching (30 points for privacy DNS, 10 for regular)
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
                    indicator_types[campaign_id].add("dns")

        # ASN matching (20 points)
        if asn and asn in self._asn_index:
            for campaign_id in self._asn_index[asn]:
                if campaign_id not in candidate_scores:
                    candidate_scores[campaign_id] = 0
                    match_reasons[campaign_id] = []
                    indicator_types[campaign_id] = set()
                candidate_scores[campaign_id] += 20
                match_reasons[campaign_id].append(f"Same ASN: {asn}")
                indicator_types[campaign_id].add("asn")

        # Visual similarity matching (perceptual hash)
        if visual_hash:
            for campaign_id, campaign in self.campaigns.items():
                if not campaign.shared_visual_hashes:
                    continue
                matched = False
                distance = None
                for candidate_hash in campaign.shared_visual_hashes:
                    distance = self._phash_distance(visual_hash, candidate_hash)
                    if distance is None:
                        continue
                    if distance <= self.VISUAL_HASH_DISTANCE:
                        matched = True
                        break
                if not matched:
                    continue
                if campaign_id not in candidate_scores:
                    candidate_scores[campaign_id] = 0
                    match_reasons[campaign_id] = []
                    indicator_types[campaign_id] = set()
                candidate_scores[campaign_id] += self.VISUAL_MATCH_SCORE
                match_reasons[campaign_id].append(
                    f"Visual similarity (phash distance {distance})"
                )
                indicator_types[campaign_id].add("visual")

        # Find best matching campaign
        if candidate_scores:
            best_campaign_id = max(candidate_scores, key=candidate_scores.get)
            best_score = candidate_scores[best_campaign_id]
            types_matched = len(indicator_types.get(best_campaign_id, set()))

            # Require BOTH:
            # 1. Minimum score of 50 (up from 40)
            # 2. At least 2 different indicator types matched
            #    (prevents matching on just a generic kit or just ASN)
            if best_score >= 50 and types_matched >= 2:
                return CampaignMatch(
                    campaign=self.campaigns[best_campaign_id],
                    match_reasons=match_reasons[best_campaign_id],
                    match_score=min(best_score, 100),
                )
            elif best_score >= 50:
                # Log when we reject a match for having only one indicator type
                logger.debug(
                    f"Rejected campaign match for {domain}: score={best_score} "
                    f"but only {types_matched} indicator type(s)"
                )

        # No match found
        return CampaignMatch(
            campaign=None,
            match_reasons=[],
            match_score=0,
        )

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
        """
        Add domain to appropriate campaign, creating new one if needed.

        Returns (campaign, is_new) tuple.
        """
        # Normalize backends to domains
        backend_domains = []
        for b in backends:
            bd = self._extract_backend_domain(b)
            if bd:
                backend_domains.append(bd)

        # Try to find matching campaign
        match = self.find_matching_campaign(
            domain=domain,
            backends=backend_domains,
            kit_matches=kit_matches,
            nameservers=[ns.lower() for ns in nameservers],
            asn=asn,
            html_hash=html_hash,
            visual_hash=visual_hash,
        )

        # Create member
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
            # Add to existing campaign
            campaign = match.campaign

            # Check if domain already in campaign
            existing_domains = {m.domain for m in campaign.members}
            if domain not in existing_domains:
                campaign.members.append(member)
                campaign.updated_at = datetime.now()

                # Update shared indicators
                campaign.shared_backends.update(backend_domains)
                campaign.shared_kits.update(kit_matches)
                campaign.shared_nameservers.update(ns.lower() for ns in nameservers)
                if asn:
                    campaign.shared_asns.add(asn)
                if visual_hash:
                    campaign.shared_visual_hashes.add(visual_hash)

                # Recalculate confidence based on campaign size and indicator overlap
                campaign.confidence = self._calculate_campaign_confidence(campaign)

                # Update indices
                self._index_campaign(campaign)
                self._save_campaigns()

                logger.info(
                    f"Added {domain} to campaign '{campaign.name}' "
                    f"(match: {match.match_score:.0f}%, reasons: {match.match_reasons})"
                )

            return campaign, False

        else:
            # Create new campaign
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
                confidence=50.0,  # Base confidence for new campaign
            )

            self.campaigns[campaign_id] = campaign
            self._index_campaign(campaign)
            self._save_campaigns()

            logger.info(f"Created new campaign '{campaign_name}' for {domain}")

            return campaign, True

    def _calculate_campaign_confidence(self, campaign: ThreatCampaign) -> float:
        """
        Calculate confidence score for a campaign.

        Higher confidence when:
        - More members
        - More shared indicators
        - Stronger indicator types (backends > kits > DNS)
        """
        score = 0.0

        # Member count (up to 30 points)
        member_count = len(campaign.members)
        score += min(member_count * 10, 30)

        # Shared backends (up to 40 points)
        if campaign.shared_backends:
            score += min(len(campaign.shared_backends) * 20, 40)

        # Shared kits (up to 20 points)
        if campaign.shared_kits:
            score += min(len(campaign.shared_kits) * 10, 20)

        # Shared nameservers (up to 10 points)
        if campaign.shared_nameservers:
            # Extra points for privacy DNS
            privacy_count = sum(
                1 for ns in campaign.shared_nameservers
                if any(p in ns for p in ["njalla", "1984", "orangewebsite"])
            )
            score += min(privacy_count * 5 + len(campaign.shared_nameservers) * 2, 10)

        return min(score, 100)

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
        """Get summary information about a campaign."""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return None

        return {
            "campaign_id": campaign.campaign_id,
            "name": campaign.name,
            "member_count": len(campaign.members),
            "domains": [m.domain for m in campaign.members],
            "shared_backends": list(campaign.shared_backends),
            "shared_kits": list(campaign.shared_kits),
            "shared_nameservers": list(campaign.shared_nameservers),
            "shared_asns": list(campaign.shared_asns),
            "confidence": campaign.confidence,
            "first_seen": campaign.created_at.isoformat(),
            "last_updated": campaign.updated_at.isoformat(),
            "actor_id": campaign.actor_id,
            "actor_notes": campaign.actor_notes,
        }

    def get_all_campaigns(self) -> List[Dict]:
        """Get summary of all campaigns."""
        return [
            self.get_campaign_summary(cid)
            for cid in self.campaigns
        ]

    def get_stats(self) -> Dict:
        """Get campaign statistics."""
        total_domains = sum(len(c.members) for c in self.campaigns.values())

        return {
            "total_campaigns": len(self.campaigns),
            "total_campaign_domains": total_domains,
            "unique_backends": len(self._backend_index),
            "unique_kits": len(self._kit_index),
            "avg_campaign_size": total_domains / len(self.campaigns) if self.campaigns else 0,
        }


@dataclass
class CampaignAnalysisResult:
    """Result of campaign analysis for a domain."""
    campaign_id: Optional[str]
    campaign_name: Optional[str]
    is_new_campaign: bool
    related_domains: List[str]
    match_reasons: List[str]
    confidence: float

    def to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "campaign_name": self.campaign_name,
            "is_new_campaign": self.is_new_campaign,
            "related_domains": self.related_domains,
            "match_reasons": self.match_reasons,
            "confidence": self.confidence,
        }


def analyze_for_campaign(
    manager: ThreatCampaignManager,
    domain: str,
    detection_result: dict,
    infrastructure: Optional[dict] = None,
) -> CampaignAnalysisResult:
    """
    Analyze a detection result and add to appropriate campaign.

    Args:
        manager: ThreatCampaignManager instance
        domain: Domain being analyzed
        detection_result: Result from detector.detect()
        infrastructure: Result from infrastructure analyzer

    Returns:
        CampaignAnalysisResult with campaign info
    """
    # Extract relevant data from detection result
    backends = []

    # Get backends from suspicious_endpoints
    for endpoint in detection_result.get("suspicious_endpoints", []):
        if isinstance(endpoint, str):
            backends.append(endpoint)

    # Get kit matches
    kit_matches = detection_result.get("kit_matches", [])
    if isinstance(kit_matches, list) and kit_matches:
        # Handle both string and tuple formats
        kit_matches = [
            k[0] if isinstance(k, tuple) else k
            for k in kit_matches
        ]

    visual_hash = detection_result.get("visual_hash")

    # Get infrastructure data
    nameservers = []
    asn = None
    ip_address = None

    if infrastructure:
        nameservers = infrastructure.get("nameservers", [])
        if isinstance(nameservers, list):
            nameservers = [ns for ns in nameservers if isinstance(ns, str)]

        asn = infrastructure.get("asn")
        ip_address = infrastructure.get("ip")

    # Add to campaign
    campaign, is_new = manager.add_to_campaign(
        domain=domain,
        score=detection_result.get("score", 0),
        backends=backends,
        kit_matches=kit_matches,
        nameservers=nameservers,
        asn=asn,
        ip_address=ip_address,
        visual_hash=visual_hash,
    )

    # Get related domains (excluding self)
    related = [m.domain for m in campaign.members if m.domain != domain]

    # Build match reasons for display
    match_reasons = []
    if not is_new:
        if campaign.shared_backends:
            match_reasons.append(f"Shared backends: {', '.join(list(campaign.shared_backends)[:3])}")
        if campaign.shared_kits:
            match_reasons.append(f"Same kit: {', '.join(campaign.shared_kits)}")
        if related:
            match_reasons.append(f"Related to: {', '.join(related[:3])}")

    return CampaignAnalysisResult(
        campaign_id=campaign.campaign_id,
        campaign_name=campaign.name,
        is_new_campaign=is_new,
        related_domains=related,
        match_reasons=match_reasons,
        confidence=campaign.confidence,
    )
