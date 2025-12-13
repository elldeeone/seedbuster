"""
Layer 5: Threat Clustering

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
class ClusterMember:
    """A domain that belongs to a threat cluster."""
    domain: str
    added_at: datetime
    score: int
    backends: List[str] = field(default_factory=list)
    kit_matches: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    ip_address: Optional[str] = None
    asn: Optional[str] = None
    html_hash: Optional[str] = None

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
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ClusterMember":
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
        )


@dataclass
class ThreatCluster:
    """A cluster of related phishing sites."""
    cluster_id: str
    name: str  # Human-readable name like "kaspa_stealer_campaign_1"
    created_at: datetime
    updated_at: datetime
    members: List[ClusterMember] = field(default_factory=list)

    # Shared indicators that define this cluster
    shared_backends: Set[str] = field(default_factory=set)
    shared_nameservers: Set[str] = field(default_factory=set)
    shared_kits: Set[str] = field(default_factory=set)
    shared_asns: Set[str] = field(default_factory=set)

    # Threat actor attribution (optional)
    actor_id: Optional[str] = None
    actor_notes: str = ""

    # Confidence in cluster validity
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "members": [m.to_dict() for m in self.members],
            "shared_backends": list(self.shared_backends),
            "shared_nameservers": list(self.shared_nameservers),
            "shared_kits": list(self.shared_kits),
            "shared_asns": list(self.shared_asns),
            "actor_id": self.actor_id,
            "actor_notes": self.actor_notes,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ThreatCluster":
        cluster = cls(
            cluster_id=data["cluster_id"],
            name=data["name"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            actor_id=data.get("actor_id"),
            actor_notes=data.get("actor_notes", ""),
            confidence=data.get("confidence", 0.0),
        )
        cluster.members = [ClusterMember.from_dict(m) for m in data.get("members", [])]
        cluster.shared_backends = set(data.get("shared_backends", []))
        cluster.shared_nameservers = set(data.get("shared_nameservers", []))
        cluster.shared_kits = set(data.get("shared_kits", []))
        cluster.shared_asns = set(data.get("shared_asns", []))
        return cluster


@dataclass
class ClusterMatch:
    """Result of trying to match a domain to existing clusters."""
    cluster: Optional[ThreatCluster]
    match_reasons: List[str]
    match_score: float  # 0-100
    is_new_cluster: bool = False


class ThreatClusterManager:
    """
    Manages threat clusters - groups of related phishing sites.

    Clustering is based on:
    1. Shared backend infrastructure (highest weight)
    2. Same phishing kit signatures
    3. Common nameservers (especially privacy DNS)
    4. Same ASN/hosting provider
    5. HTML content similarity
    """

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.clusters_file = data_dir / "clusters.json"
        self.clusters: Dict[str, ThreatCluster] = {}

        # Index for fast lookups
        self._backend_index: Dict[str, Set[str]] = {}  # backend -> cluster_ids
        self._kit_index: Dict[str, Set[str]] = {}  # kit -> cluster_ids
        self._ns_index: Dict[str, Set[str]] = {}  # nameserver -> cluster_ids
        self._asn_index: Dict[str, Set[str]] = {}  # asn -> cluster_ids
        self._domain_index: Dict[str, str] = {}  # domain -> cluster_id

        self._load_clusters()

    def _load_clusters(self):
        """Load clusters from disk."""
        if self.clusters_file.exists():
            try:
                with open(self.clusters_file, "r") as f:
                    data = json.load(f)

                for cluster_data in data.get("clusters", []):
                    cluster = ThreatCluster.from_dict(cluster_data)
                    self.clusters[cluster.cluster_id] = cluster
                    self._index_cluster(cluster)

                logger.info(f"Loaded {len(self.clusters)} threat clusters")
            except Exception as e:
                logger.error(f"Failed to load clusters: {e}")

    def _save_clusters(self):
        """Save clusters to disk."""
        self.data_dir.mkdir(parents=True, exist_ok=True)

        data = {
            "version": "1.0",
            "saved_at": datetime.now().isoformat(),
            "clusters": [c.to_dict() for c in self.clusters.values()],
        }

        with open(self.clusters_file, "w") as f:
            json.dump(data, f, indent=2)

    def _index_cluster(self, cluster: ThreatCluster):
        """Add cluster to lookup indices."""
        for backend in cluster.shared_backends:
            if backend not in self._backend_index:
                self._backend_index[backend] = set()
            self._backend_index[backend].add(cluster.cluster_id)

        for kit in cluster.shared_kits:
            if kit not in self._kit_index:
                self._kit_index[kit] = set()
            self._kit_index[kit].add(cluster.cluster_id)

        for ns in cluster.shared_nameservers:
            if ns not in self._ns_index:
                self._ns_index[ns] = set()
            self._ns_index[ns].add(cluster.cluster_id)

        for asn in cluster.shared_asns:
            if asn not in self._asn_index:
                self._asn_index[asn] = set()
            self._asn_index[asn].add(cluster.cluster_id)

        for member in cluster.members:
            self._domain_index[member.domain] = cluster.cluster_id

    def _generate_cluster_id(self) -> str:
        """Generate unique cluster ID."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = hashlib.md5(str(datetime.now().timestamp()).encode()).hexdigest()[:6]
        return f"cluster_{timestamp}_{random_suffix}"

    def _generate_cluster_name(self, backends: List[str], kits: List[str]) -> str:
        """Generate human-readable cluster name."""
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

    def find_matching_cluster(
        self,
        domain: str,
        backends: List[str],
        kit_matches: List[str],
        nameservers: List[str],
        asn: Optional[str] = None,
        html_hash: Optional[str] = None,
    ) -> ClusterMatch:
        """
        Find if domain matches an existing cluster.

        Returns ClusterMatch with:
        - cluster: Matching cluster or None
        - match_reasons: Why it matched
        - match_score: Confidence of match (0-100)
        """
        # Check if domain already in a cluster
        if domain in self._domain_index:
            cluster_id = self._domain_index[domain]
            cluster = self.clusters.get(cluster_id)
            if cluster:
                return ClusterMatch(
                    cluster=cluster,
                    match_reasons=["Domain already in cluster"],
                    match_score=100.0,
                )

        # Score matches against each indicator type
        candidate_scores: Dict[str, float] = {}  # cluster_id -> score
        match_reasons: Dict[str, List[str]] = {}  # cluster_id -> reasons

        # Backend matching (highest weight: 50 points)
        for backend in backends:
            backend_domain = self._extract_backend_domain(backend)
            if backend_domain and backend_domain in self._backend_index:
                for cluster_id in self._backend_index[backend_domain]:
                    if cluster_id not in candidate_scores:
                        candidate_scores[cluster_id] = 0
                        match_reasons[cluster_id] = []
                    candidate_scores[cluster_id] += 50
                    match_reasons[cluster_id].append(f"Shared backend: {backend_domain}")

        # Kit signature matching (40 points)
        for kit in kit_matches:
            if kit in self._kit_index:
                for cluster_id in self._kit_index[kit]:
                    if cluster_id not in candidate_scores:
                        candidate_scores[cluster_id] = 0
                        match_reasons[cluster_id] = []
                    candidate_scores[cluster_id] += 40
                    match_reasons[cluster_id].append(f"Same kit: {kit}")

        # Nameserver matching (30 points for privacy DNS, 10 for regular)
        privacy_ns_patterns = ["njalla", "1984", "orangewebsite"]
        for ns in nameservers:
            ns_lower = ns.lower()
            is_privacy = any(p in ns_lower for p in privacy_ns_patterns)
            points = 30 if is_privacy else 10

            if ns_lower in self._ns_index:
                for cluster_id in self._ns_index[ns_lower]:
                    if cluster_id not in candidate_scores:
                        candidate_scores[cluster_id] = 0
                        match_reasons[cluster_id] = []
                    candidate_scores[cluster_id] += points
                    ns_type = "privacy DNS" if is_privacy else "nameserver"
                    match_reasons[cluster_id].append(f"Shared {ns_type}: {ns}")

        # ASN matching (20 points)
        if asn and asn in self._asn_index:
            for cluster_id in self._asn_index[asn]:
                if cluster_id not in candidate_scores:
                    candidate_scores[cluster_id] = 0
                    match_reasons[cluster_id] = []
                candidate_scores[cluster_id] += 20
                match_reasons[cluster_id].append(f"Same ASN: {asn}")

        # Find best matching cluster
        if candidate_scores:
            best_cluster_id = max(candidate_scores, key=candidate_scores.get)
            best_score = candidate_scores[best_cluster_id]

            # Require minimum score of 40 to match
            if best_score >= 40:
                return ClusterMatch(
                    cluster=self.clusters[best_cluster_id],
                    match_reasons=match_reasons[best_cluster_id],
                    match_score=min(best_score, 100),
                )

        # No match found
        return ClusterMatch(
            cluster=None,
            match_reasons=[],
            match_score=0,
        )

    def add_to_cluster(
        self,
        domain: str,
        score: int,
        backends: List[str],
        kit_matches: List[str],
        nameservers: List[str],
        asn: Optional[str] = None,
        ip_address: Optional[str] = None,
        html_hash: Optional[str] = None,
    ) -> Tuple[ThreatCluster, bool]:
        """
        Add domain to appropriate cluster, creating new one if needed.

        Returns (cluster, is_new) tuple.
        """
        # Normalize backends to domains
        backend_domains = []
        for b in backends:
            bd = self._extract_backend_domain(b)
            if bd:
                backend_domains.append(bd)

        # Try to find matching cluster
        match = self.find_matching_cluster(
            domain=domain,
            backends=backend_domains,
            kit_matches=kit_matches,
            nameservers=[ns.lower() for ns in nameservers],
            asn=asn,
            html_hash=html_hash,
        )

        # Create member
        member = ClusterMember(
            domain=domain,
            added_at=datetime.now(),
            score=score,
            backends=backend_domains,
            kit_matches=kit_matches,
            nameservers=[ns.lower() for ns in nameservers],
            ip_address=ip_address,
            asn=asn,
            html_hash=html_hash,
        )

        if match.cluster and match.match_score >= 40:
            # Add to existing cluster
            cluster = match.cluster

            # Check if domain already in cluster
            existing_domains = {m.domain for m in cluster.members}
            if domain not in existing_domains:
                cluster.members.append(member)
                cluster.updated_at = datetime.now()

                # Update shared indicators
                cluster.shared_backends.update(backend_domains)
                cluster.shared_kits.update(kit_matches)
                cluster.shared_nameservers.update(ns.lower() for ns in nameservers)
                if asn:
                    cluster.shared_asns.add(asn)

                # Recalculate confidence based on cluster size and indicator overlap
                cluster.confidence = self._calculate_cluster_confidence(cluster)

                # Update indices
                self._index_cluster(cluster)
                self._save_clusters()

                logger.info(
                    f"Added {domain} to cluster '{cluster.name}' "
                    f"(match: {match.match_score:.0f}%, reasons: {match.match_reasons})"
                )

            return cluster, False

        else:
            # Create new cluster
            cluster_id = self._generate_cluster_id()
            cluster_name = self._generate_cluster_name(backend_domains, kit_matches)

            cluster = ThreatCluster(
                cluster_id=cluster_id,
                name=cluster_name,
                created_at=datetime.now(),
                updated_at=datetime.now(),
                members=[member],
                shared_backends=set(backend_domains),
                shared_kits=set(kit_matches),
                shared_nameservers=set(ns.lower() for ns in nameservers),
                shared_asns={asn} if asn else set(),
                confidence=50.0,  # Base confidence for new cluster
            )

            self.clusters[cluster_id] = cluster
            self._index_cluster(cluster)
            self._save_clusters()

            logger.info(f"Created new cluster '{cluster_name}' for {domain}")

            return cluster, True

    def _calculate_cluster_confidence(self, cluster: ThreatCluster) -> float:
        """
        Calculate confidence score for a cluster.

        Higher confidence when:
        - More members
        - More shared indicators
        - Stronger indicator types (backends > kits > DNS)
        """
        score = 0.0

        # Member count (up to 30 points)
        member_count = len(cluster.members)
        score += min(member_count * 10, 30)

        # Shared backends (up to 40 points)
        if cluster.shared_backends:
            score += min(len(cluster.shared_backends) * 20, 40)

        # Shared kits (up to 20 points)
        if cluster.shared_kits:
            score += min(len(cluster.shared_kits) * 10, 20)

        # Shared nameservers (up to 10 points)
        if cluster.shared_nameservers:
            # Extra points for privacy DNS
            privacy_count = sum(
                1 for ns in cluster.shared_nameservers
                if any(p in ns for p in ["njalla", "1984", "orangewebsite"])
            )
            score += min(privacy_count * 5 + len(cluster.shared_nameservers) * 2, 10)

        return min(score, 100)

    def get_cluster_for_domain(self, domain: str) -> Optional[ThreatCluster]:
        """Get cluster containing a domain."""
        cluster_id = self._domain_index.get(domain)
        if cluster_id:
            return self.clusters.get(cluster_id)
        return None

    def get_related_domains(self, domain: str) -> List[str]:
        """Get all domains related to a given domain via clustering."""
        cluster = self.get_cluster_for_domain(domain)
        if cluster:
            return [m.domain for m in cluster.members if m.domain != domain]
        return []

    def get_cluster_summary(self, cluster_id: str) -> Optional[Dict]:
        """Get summary information about a cluster."""
        cluster = self.clusters.get(cluster_id)
        if not cluster:
            return None

        return {
            "id": cluster.cluster_id,
            "name": cluster.name,
            "member_count": len(cluster.members),
            "domains": [m.domain for m in cluster.members],
            "shared_backends": list(cluster.shared_backends),
            "shared_kits": list(cluster.shared_kits),
            "confidence": cluster.confidence,
            "first_seen": cluster.created_at.isoformat(),
            "last_updated": cluster.updated_at.isoformat(),
            "actor_id": cluster.actor_id,
        }

    def get_all_clusters(self) -> List[Dict]:
        """Get summary of all clusters."""
        return [
            self.get_cluster_summary(cid)
            for cid in self.clusters
        ]

    def get_stats(self) -> Dict:
        """Get clustering statistics."""
        total_domains = sum(len(c.members) for c in self.clusters.values())

        return {
            "total_clusters": len(self.clusters),
            "total_clustered_domains": total_domains,
            "unique_backends": len(self._backend_index),
            "unique_kits": len(self._kit_index),
            "avg_cluster_size": total_domains / len(self.clusters) if self.clusters else 0,
        }


@dataclass
class ClusterAnalysisResult:
    """Result of cluster analysis for a domain."""
    cluster_id: Optional[str]
    cluster_name: Optional[str]
    is_new_cluster: bool
    related_domains: List[str]
    match_reasons: List[str]
    confidence: float

    def to_dict(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "cluster_name": self.cluster_name,
            "is_new_cluster": self.is_new_cluster,
            "related_domains": self.related_domains,
            "match_reasons": self.match_reasons,
            "confidence": self.confidence,
        }


def analyze_for_clustering(
    manager: ThreatClusterManager,
    domain: str,
    detection_result: dict,
    infrastructure: Optional[dict] = None,
) -> ClusterAnalysisResult:
    """
    Analyze a detection result and add to appropriate cluster.

    Args:
        manager: ThreatClusterManager instance
        domain: Domain being analyzed
        detection_result: Result from detector.detect()
        infrastructure: Result from infrastructure analyzer

    Returns:
        ClusterAnalysisResult with cluster info
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

    # Add to cluster
    cluster, is_new = manager.add_to_cluster(
        domain=domain,
        score=detection_result.get("score", 0),
        backends=backends,
        kit_matches=kit_matches,
        nameservers=nameservers,
        asn=asn,
        ip_address=ip_address,
    )

    # Get related domains (excluding self)
    related = [m.domain for m in cluster.members if m.domain != domain]

    # Build match reasons for display
    match_reasons = []
    if not is_new:
        if cluster.shared_backends:
            match_reasons.append(f"Shared backends: {', '.join(list(cluster.shared_backends)[:3])}")
        if cluster.shared_kits:
            match_reasons.append(f"Same kit: {', '.join(cluster.shared_kits)}")
        if related:
            match_reasons.append(f"Related to: {', '.join(related[:3])}")

    return ClusterAnalysisResult(
        cluster_id=cluster.cluster_id,
        cluster_name=cluster.name,
        is_new_cluster=is_new,
        related_domains=related,
        match_reasons=match_reasons,
        confidence=cluster.confidence,
    )
