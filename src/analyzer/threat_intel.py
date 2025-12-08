"""Threat intelligence loader and manager for SeedBuster."""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ThreatIndicator:
    """A single threat indicator."""
    value: str
    type: str
    confidence: str = "medium"
    score_modifier: int = 0
    first_seen: Optional[str] = None
    source: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class ThreatIntel:
    """Loaded threat intelligence data."""

    version: str = "1.0"
    last_updated: Optional[str] = None

    # Organized indicators
    malicious_domains: list[ThreatIndicator] = field(default_factory=list)
    malicious_patterns: list[ThreatIndicator] = field(default_factory=list)
    api_keys: list[ThreatIndicator] = field(default_factory=list)
    suspicious_hosting: list[ThreatIndicator] = field(default_factory=list)
    antibot_services: list[ThreatIndicator] = field(default_factory=list)
    scammer_signatures: list[dict] = field(default_factory=list)

    def is_known_malicious(self, domain: str) -> tuple[bool, Optional[ThreatIndicator]]:
        """Check if a domain is known malicious."""
        domain_lower = domain.lower()
        for indicator in self.malicious_domains:
            if indicator.value.lower() in domain_lower:
                return True, indicator
        return False, None

    def check_malicious_patterns(self, url: str) -> list[ThreatIndicator]:
        """Check URL against malicious patterns."""
        matches = []
        for indicator in self.malicious_patterns:
            if re.search(indicator.value, url, re.I):
                matches.append(indicator)
        return matches

    def check_suspicious_hosting(self, domain: str) -> list[ThreatIndicator]:
        """Check if domain uses suspicious hosting."""
        matches = []
        domain_lower = domain.lower()
        for indicator in self.suspicious_hosting:
            if indicator.value.lower() in domain_lower:
                matches.append(indicator)
        return matches

    def check_antibot_services(self, domains: list[str]) -> list[ThreatIndicator]:
        """Check for anti-bot service usage."""
        matches = []
        for domain in domains:
            domain_lower = domain.lower()
            for indicator in self.antibot_services:
                if indicator.value.lower() in domain_lower:
                    matches.append(indicator)
        return matches

    def check_api_keys(self, content: str) -> list[ThreatIndicator]:
        """Check content for known malicious API keys."""
        matches = []
        for indicator in self.api_keys:
            if indicator.value in content:
                matches.append(indicator)
        return matches

    def check_scammer_signatures(self, content: str) -> list[dict]:
        """Check for known scammer infrastructure signatures."""
        matches = []
        content_lower = content.lower()
        for sig in self.scammer_signatures:
            indicators = sig.get("indicators", [])
            matched = sum(1 for ind in indicators if ind.lower() in content_lower)
            if matched >= 2 or (matched == len(indicators) and matched > 0):
                matches.append(sig)
        return matches


class ThreatIntelLoader:
    """Loads and manages threat intelligence data."""

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.intel_file = config_dir / "threat_intel.yaml"
        self._intel: Optional[ThreatIntel] = None
        self._load_time: Optional[float] = None

    def load(self) -> ThreatIntel:
        """Load threat intelligence from file."""
        if not self.intel_file.exists():
            logger.warning(f"Threat intel file not found: {self.intel_file}")
            return ThreatIntel()

        try:
            with open(self.intel_file) as f:
                data = yaml.safe_load(f)

            intel = ThreatIntel(
                version=data.get("version", "1.0"),
                last_updated=data.get("last_updated"),
            )

            # Load malicious domains
            for item in data.get("malicious_domains", []):
                intel.malicious_domains.append(ThreatIndicator(
                    value=item["domain"],
                    type=item.get("type", "malicious"),
                    confidence=item.get("confidence", "medium"),
                    first_seen=item.get("first_seen"),
                    source=item.get("source"),
                    notes=item.get("notes"),
                ))

            # Load malicious patterns
            for item in data.get("malicious_patterns", []):
                intel.malicious_patterns.append(ThreatIndicator(
                    value=item["pattern"],
                    type=item.get("type", "pattern"),
                    confidence=item.get("confidence", "medium"),
                    notes=item.get("notes"),
                ))

            # Load API keys
            for item in data.get("api_keys", []):
                intel.api_keys.append(ThreatIndicator(
                    value=item["key"],
                    type=item.get("service", "api_key"),
                    first_seen=item.get("first_seen"),
                    notes=item.get("associated_domain"),
                ))

            # Load suspicious hosting patterns
            for item in data.get("suspicious_hosting", []):
                intel.suspicious_hosting.append(ThreatIndicator(
                    value=item["pattern"],
                    type="hosting",
                    score_modifier=item.get("score_modifier", 10),
                    notes=item.get("notes"),
                ))

            # Load anti-bot services
            for item in data.get("antibot_services", []):
                intel.antibot_services.append(ThreatIndicator(
                    value=item["domain"],
                    type="antibot",
                    score_modifier=item.get("score_modifier", 15),
                ))

            # Load scammer signatures
            intel.scammer_signatures = data.get("scammer_signatures", [])

            self._intel = intel
            logger.info(f"Loaded threat intel v{intel.version} ({len(intel.malicious_domains)} domains, "
                       f"{len(intel.malicious_patterns)} patterns, {len(intel.api_keys)} API keys)")

            return intel

        except Exception as e:
            logger.error(f"Error loading threat intel: {e}")
            return ThreatIntel()

    def get(self) -> ThreatIntel:
        """Get loaded threat intel, loading if necessary."""
        if self._intel is None:
            return self.load()
        return self._intel

    def reload(self) -> ThreatIntel:
        """Force reload threat intel from file."""
        self._intel = None
        return self.load()
