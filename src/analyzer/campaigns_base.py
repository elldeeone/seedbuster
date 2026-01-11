"""Threat campaign manager base configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Set

from ..utils.domain_similarity import (
    DOMAIN_SIMILARITY_MIN_LEN as SIMILARITY_MIN_LEN,
    DOMAIN_SIMILARITY_THRESHOLD as SIMILARITY_THRESHOLD,
)
from .campaigns_models import ThreatCampaign


class ThreatCampaignManagerBase:
    """Base class for threat campaign manager."""

    VISUAL_HASH_DISTANCE_STRICT = 4
    VISUAL_HASH_DISTANCE_LOOSE = 24
    VISUAL_MATCH_SCORE = 40
    VISUAL_MATCH_SCORE_LOOSE = 30
    DOMAIN_SIMILARITY_SCORE = 20
    DOMAIN_SIMILARITY_THRESHOLD = SIMILARITY_THRESHOLD
    DOMAIN_SIMILARITY_MIN_LEN = SIMILARITY_MIN_LEN

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._migrate_legacy_storage()
        self.campaigns_file = data_dir / "campaigns.json"
        self.campaigns: Dict[str, ThreatCampaign] = {}

        # Index for fast lookups
        self._backend_index: Dict[str, Set[str]] = {}
        self._kit_index: Dict[str, Set[str]] = {}
        self._ns_index: Dict[str, Set[str]] = {}
        self._asn_index: Dict[str, Set[str]] = {}
        self._domain_index: Dict[str, str] = {}

        self._load_campaigns()
