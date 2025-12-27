"""Auto-update threat intelligence when new malicious domains are confirmed."""

import logging
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class LearningResult:
    """Result of a threat intel learning operation."""
    updated: bool
    new_domain_added: bool
    added_to_frontends: list[str]  # Gang names domain was added to
    added_to_api_keys: list[str]  # API key services domain was linked to
    version: str
    message: str


class ThreatIntelUpdater:
    """Updates threat_intel.yaml when new malicious domains are confirmed.

    Trigger conditions (any of):
    - Campaign confidence >= 90% with known campaign
    - Detection of known malicious backends (whale-app, walrus-app, etc.)
    - Matched API keys from known campaigns
    """

    # Minimum confidence to auto-add a domain
    MIN_CAMPAIGN_CONFIDENCE = 90.0
    MIN_ANALYSIS_SCORE = 80

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.intel_file = config_dir / "threat_intel.yaml"
        self._lock = threading.Lock()

    def should_learn(
        self,
        domain: str,
        analysis_score: int,
        campaign_confidence: float,
        campaign_name: Optional[str],
        matched_backends: list[str],
        matched_api_keys: list[str],
    ) -> bool:
        """Determine if we should auto-learn from this detection."""
        # Must meet minimum score
        if analysis_score < self.MIN_ANALYSIS_SCORE:
            return False

        # Any of these conditions triggers learning
        if campaign_confidence >= self.MIN_CAMPAIGN_CONFIDENCE and campaign_name:
            return True

        if len(matched_backends) >= 1:
            return True

        if len(matched_api_keys) >= 1:
            return True

        return False

    def learn(
        self,
        domain: str,
        analysis_score: int,
        campaign_confidence: float,
        campaign_name: Optional[str],
        matched_backends: list[str],
        matched_api_keys: list[str],
        detection_source: str = "seedbuster_auto",
    ) -> LearningResult:
        """Learn from a confirmed malicious domain and update threat intel.

        Args:
            domain: The confirmed malicious domain
            analysis_score: Final analysis score (0-100)
            campaign_confidence: Confidence of campaign match (0-100)
            campaign_name: Name of matched campaign
            matched_backends: List of matched malicious backend domains
            matched_api_keys: List of matched API key services
            detection_source: Source of detection for notes

        Returns:
            LearningResult with details of what was updated
        """
        if not self.intel_file.exists():
            return LearningResult(
                updated=False,
                new_domain_added=False,
                added_to_frontends=[],
                added_to_api_keys=[],
                version="",
                message="Threat intel file not found",
            )

        with self._lock:
            try:
                # Load current intel
                with open(self.intel_file) as f:
                    data = yaml.safe_load(f)

                updated = False
                new_domain_added = False
                added_to_frontends = []
                added_to_api_keys = []

                # Check if domain already exists in malicious_domains
                existing_domains = {d["domain"].lower() for d in data.get("malicious_domains", [])}
                domain_lower = domain.lower()

                if domain_lower not in existing_domains:
                    # Add new domain to malicious_domains list
                    new_entry = {
                        "domain": domain,
                        "type": "phishing_host",
                        "confidence": "high" if analysis_score >= 90 else "medium",
                        "first_seen": datetime.now().strftime("%Y-%m-%d"),
                        "source": detection_source,
                        "notes": f"Auto-detected: score={analysis_score}",
                    }

                    # Add campaign info to notes if available
                    if campaign_name:
                        new_entry["notes"] += f", campaign={campaign_name}"
                    if matched_backends:
                        new_entry["notes"] += f", backends={','.join(matched_backends[:2])}"

                    data.setdefault("malicious_domains", []).append(new_entry)
                    new_domain_added = True
                    updated = True
                    logger.info(f"Threat intel: Added new malicious domain: {domain}")

                # Update scammer_signatures - add to known_frontends
                for sig in data.get("scammer_signatures", []):
                    sig_name = sig.get("name", "")
                    indicators = sig.get("indicators", [])

                    # Check if any matched backends match this signature's indicators
                    matched_sig = False
                    for backend in matched_backends:
                        for indicator in indicators:
                            if indicator.lower() in backend.lower():
                                matched_sig = True
                                break
                        if matched_sig:
                            break

                    # Also match by campaign name
                    if campaign_name and sig_name.lower() in campaign_name.lower():
                        matched_sig = True

                    if matched_sig:
                        frontends = sig.setdefault("known_frontends", [])
                        if domain not in frontends:
                            frontends.append(domain)
                            added_to_frontends.append(sig_name)
                            updated = True
                            logger.info(f"Threat intel: Added {domain} to {sig_name} frontends")

                # Update api_keys - add to associated_domains
                for api_key in data.get("api_keys", []):
                    service = api_key.get("service", "")

                    # Check if this API key's service was matched
                    matched_key = False
                    for matched_service in matched_api_keys:
                        if matched_service.lower() in service.lower():
                            matched_key = True
                            break

                    # Also check if domain uses same backends as other domains with this key
                    if any(backend in matched_backends for backend in ["whale-app", "walrus-app"]):
                        # If using whale/walrus backends, likely uses same API keys
                        if service in ["ipdata.co", "whale_backend"]:
                            matched_key = True

                    if matched_key:
                        assoc_domains = api_key.setdefault("associated_domains", [])
                        if domain not in assoc_domains:
                            assoc_domains.append(domain)
                            added_to_api_keys.append(service)
                            updated = True
                            logger.info(f"Threat intel: Added {domain} to {service} associated_domains")

                # Update version and timestamp if we made changes
                if updated:
                    old_version = data.get("version", "1.0")
                    # Increment patch version
                    try:
                        parts = old_version.split(".")
                        parts[-1] = str(int(parts[-1]) + 1)
                        new_version = ".".join(parts)
                    except (ValueError, IndexError):
                        new_version = old_version + ".1"

                    data["version"] = new_version
                    data["last_updated"] = datetime.now().strftime("%Y-%m-%d")

                    # Write back to file
                    with open(self.intel_file, "w") as f:
                        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

                    message = f"Learned: {domain}"
                    if new_domain_added:
                        message += " (new domain)"
                    if added_to_frontends:
                        message += f", frontends: {added_to_frontends}"
                    if added_to_api_keys:
                        message += f", api_keys: {added_to_api_keys}"

                    logger.info(f"Threat intel updated to v{new_version}: {message}")

                    return LearningResult(
                        updated=True,
                        new_domain_added=new_domain_added,
                        added_to_frontends=added_to_frontends,
                        added_to_api_keys=added_to_api_keys,
                        version=new_version,
                        message=message,
                    )
                else:
                    return LearningResult(
                        updated=False,
                        new_domain_added=False,
                        added_to_frontends=[],
                        added_to_api_keys=[],
                        version=data.get("version", ""),
                        message=f"Domain {domain} already in threat intel",
                    )

            except Exception as e:
                logger.error(f"Failed to update threat intel: {e}")
                return LearningResult(
                    updated=False,
                    new_domain_added=False,
                    added_to_frontends=[],
                    added_to_api_keys=[],
                    version="",
                    message=f"Error: {e}",
                )

    def extract_matched_backends(self, suspicious_endpoints: list[str]) -> list[str]:
        """Extract known backend identifiers from suspicious endpoints.

        Looks for patterns like 'whale-app', 'walrus-app', 'kaspa-backend', etc.
        """
        known_patterns = [
            "whale-app",
            "walrus-app",
            "kaspa-backend",
        ]

        matched = []
        for endpoint in suspicious_endpoints:
            endpoint_lower = endpoint.lower()
            for pattern in known_patterns:
                if pattern in endpoint_lower and pattern not in matched:
                    matched.append(pattern)

        return matched

    def extract_matched_api_keys(self, reasons: list[str]) -> list[str]:
        """Extract matched API key services from detection reasons."""
        services = []

        # Look for ipdata.co usage
        if any("ipdata" in r.lower() for r in reasons):
            services.append("ipdata.co")

        # Look for whale backend key usage
        if any("whale" in r.lower() and "backend" in r.lower() for r in reasons):
            services.append("whale_backend")

        return services
