"""Temporal Intelligence for SeedBuster.

Tracks domain behavior over time to detect cloaking patterns,
schedule re-scans, and identify temporal evasion techniques.
"""

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional, Callable, Awaitable
import json

logger = logging.getLogger(__name__)


class ScanReason(Enum):
    """Reason for scheduling a scan."""
    INITIAL = "initial"
    RESCAN_6H = "rescan_6h"
    RESCAN_12H = "rescan_12h"
    RESCAN_24H = "rescan_24h"
    RESCAN_48H = "rescan_48h"
    RESCAN_MONTHLY = "rescan_monthly"  # For deferred (watchlist) domains
    MANUAL = "manual"
    CONTENT_CHANGE = "content_change"
    CLOAKING_CHECK = "cloaking_check"


@dataclass
class DomainSnapshot:
    """A point-in-time snapshot of domain analysis."""

    domain: str
    timestamp: datetime
    scan_reason: ScanReason

    # Content hashes for comparison
    html_hash: str = ""
    title: str = ""
    screenshot_hash: str = ""

    # Detection results
    score: int = 0
    verdict: str = ""
    reasons: list[str] = field(default_factory=list)

    # Network fingerprint
    external_domains: list[str] = field(default_factory=list)
    blocked_requests: int = 0

    # Infrastructure at time of scan
    tls_age_days: int = -1
    hosting_provider: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            "domain": self.domain,
            "timestamp": self.timestamp.isoformat(),
            "scan_reason": self.scan_reason.value,
            "html_hash": self.html_hash,
            "title": self.title,
            "screenshot_hash": self.screenshot_hash,
            "score": self.score,
            "verdict": self.verdict,
            "reasons": self.reasons,
            "external_domains": self.external_domains,
            "blocked_requests": self.blocked_requests,
            "tls_age_days": self.tls_age_days,
            "hosting_provider": self.hosting_provider,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DomainSnapshot":
        """Create from dictionary."""
        return cls(
            domain=data["domain"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            scan_reason=ScanReason(data.get("scan_reason", "initial")),
            html_hash=data.get("html_hash", ""),
            title=data.get("title", ""),
            screenshot_hash=data.get("screenshot_hash", ""),
            score=data.get("score", 0),
            verdict=data.get("verdict", ""),
            reasons=data.get("reasons", []),
            external_domains=data.get("external_domains", []),
            blocked_requests=data.get("blocked_requests", 0),
            tls_age_days=data.get("tls_age_days", -1),
            hosting_provider=data.get("hosting_provider", ""),
        )


@dataclass
class TemporalAnalysis:
    """Results of temporal analysis comparing snapshots."""

    domain: str
    snapshots_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # Change detection
    content_changed: bool = False
    title_changed: bool = False
    score_increased: bool = False
    score_decreased: bool = False

    # Cloaking indicators
    cloaking_detected: bool = False
    cloaking_confidence: float = 0.0
    cloaking_pattern: str = ""

    # Behavioral patterns
    shows_different_content: bool = False  # Different content at different times
    intermittent_malicious: bool = False   # Sometimes malicious, sometimes not
    score_variance: float = 0.0            # How much score varies

    # Risk assessment
    temporal_risk_score: int = 0
    temporal_reasons: list[str] = field(default_factory=list)

    def calculate_risk(self) -> tuple[int, list[str]]:
        """Calculate temporal risk score."""
        score = 0
        reasons = []

        if self.cloaking_detected:
            score += 25
            pattern_label = {
                "score_drop_after_detection": "score dropped after detection",
                "dynamic_content_same_title": "dynamic content with stable title",
                "verdict_flip": "verdict flips between scans",
                "inconsistent_antibot": "anti-bot behavior inconsistent",
                "seed_form_toggle": "seed form appears/disappears",
            }.get(self.cloaking_pattern, self.cloaking_pattern or "unknown")
            reasons.append(
                f"TEMPORAL: Cloaking detected ({self.cloaking_confidence:.0%}): {pattern_label}"
            )

        if self.intermittent_malicious:
            score += 20
            reasons.append("TEMPORAL: Intermittent malicious behavior")

        if self.shows_different_content:
            score += 15
            reasons.append("TEMPORAL: Content varies between scans")

        if self.score_variance > 30:
            score += 10
            reasons.append(f"TEMPORAL: High score variance ({self.score_variance:.0f})")

        if self.score_increased:
            score += 5
            reasons.append("TEMPORAL: Detection score increased over time")

        self.temporal_risk_score = score
        self.temporal_reasons = reasons
        return score, reasons


@dataclass
class ScheduledRescan:
    """A scheduled rescan task."""

    domain: str
    scheduled_time: datetime
    reason: ScanReason
    domain_id: Optional[str] = None
    attempts: int = 0
    max_attempts: int = 3


class TemporalTracker:
    """Tracks and analyzes domain behavior over time."""

    # Default rescan intervals after initial detection
    RESCAN_INTERVALS = [
        (timedelta(hours=6), ScanReason.RESCAN_6H),
        (timedelta(hours=12), ScanReason.RESCAN_12H),
        (timedelta(hours=24), ScanReason.RESCAN_24H),
        (timedelta(hours=48), ScanReason.RESCAN_48H),
    ]

    def __init__(self, storage_dir: Path):
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._rescans_file = self.storage_dir / "scheduled_rescans.json"

        # In-memory cache of snapshots
        self._snapshots: dict[str, list[DomainSnapshot]] = {}

        # Scheduled rescans
        self._scheduled: dict[str, list[ScheduledRescan]] = {}

        # Callback for triggering rescans
        self._rescan_callback: Optional[Callable[[str, ScanReason], Awaitable[None]]] = None

        # Load existing data
        self._load_snapshots()
        self._load_rescans()

    def set_rescan_callback(
        self,
        callback: Callable[[str, ScanReason], Awaitable[None]]
    ):
        """Set callback function for triggering rescans."""
        self._rescan_callback = callback

    def _get_snapshot_file(self, domain: str) -> Path:
        """Get path to domain's snapshot file."""
        safe_domain = domain.replace("/", "_").replace(":", "_")
        return self.storage_dir / f"{safe_domain}_snapshots.json"

    def _load_snapshots(self):
        """Load all snapshots from storage."""
        for file in self.storage_dir.glob("*_snapshots.json"):
            try:
                data = json.loads(file.read_text())
                domain = data.get("domain", "")
                if domain:
                    self._snapshots[domain] = [
                        DomainSnapshot.from_dict(s)
                        for s in data.get("snapshots", [])
                    ]
            except Exception as e:
                logger.warning(f"Failed to load snapshots from {file}: {e}")

    def _load_rescans(self):
        """Load scheduled rescans from disk (best-effort)."""
        if not self._rescans_file.exists():
            return
        try:
            data = json.loads(self._rescans_file.read_text())
        except Exception as exc:
            logger.warning("Failed to load scheduled rescans: %s", exc)
            return

        rescans_raw = data.get("rescans") if isinstance(data, dict) else None
        if not isinstance(rescans_raw, list):
            return

        for entry in rescans_raw:
            try:
                domain = str(entry.get("domain") or "").strip()
                if not domain:
                    continue
                scheduled_time = datetime.fromisoformat(entry.get("scheduled_time"))
                reason = ScanReason(entry.get("reason"))
                attempts = int(entry.get("attempts", 0))
                max_attempts = int(entry.get("max_attempts", 3))
                rescan = ScheduledRescan(
                    domain=domain,
                    scheduled_time=scheduled_time,
                    reason=reason,
                    attempts=attempts,
                    max_attempts=max_attempts,
                )
                if domain not in self._scheduled:
                    self._scheduled[domain] = []
                self._scheduled[domain].append(rescan)
            except Exception:
                continue

    def _save_rescans(self):
        """Persist scheduled rescans to disk."""
        data = []
        for domain, rescans in self._scheduled.items():
            for rescan in rescans:
                data.append({
                    "domain": domain,
                    "scheduled_time": rescan.scheduled_time.isoformat(),
                    "reason": rescan.reason.value,
                    "attempts": rescan.attempts,
                    "max_attempts": rescan.max_attempts,
                })
        try:
            self._rescans_file.write_text(json.dumps({"rescans": data}, indent=2))
        except Exception as exc:
            logger.warning("Failed to persist scheduled rescans: %s", exc)

    def _save_snapshots(self, domain: str):
        """Save domain snapshots to storage."""
        if domain not in self._snapshots:
            return

        file = self._get_snapshot_file(domain)
        data = {
            "domain": domain,
            "snapshots": [s.to_dict() for s in self._snapshots[domain]],
        }
        file.write_text(json.dumps(data, indent=2))

    def add_snapshot(
        self,
        domain: str,
        html: Optional[str] = None,
        title: str = "",
        screenshot: Optional[bytes] = None,
        score: int = 0,
        verdict: str = "",
        reasons: list[str] = None,
        external_domains: list[str] = None,
        blocked_requests: int = 0,
        tls_age_days: int = -1,
        hosting_provider: str = "",
        scan_reason: ScanReason = ScanReason.INITIAL,
    ) -> DomainSnapshot:
        """Add a new snapshot for a domain."""

        # Create content hashes
        html_hash = ""
        if html:
            html_hash = hashlib.sha256(html.encode()).hexdigest()[:16]

        screenshot_hash = ""
        if screenshot:
            screenshot_hash = hashlib.sha256(screenshot).hexdigest()[:16]

        snapshot = DomainSnapshot(
            domain=domain,
            timestamp=datetime.now(timezone.utc),
            scan_reason=scan_reason,
            html_hash=html_hash,
            title=title,
            screenshot_hash=screenshot_hash,
            score=score,
            verdict=verdict,
            reasons=reasons or [],
            external_domains=external_domains or [],
            blocked_requests=blocked_requests,
            tls_age_days=tls_age_days,
            hosting_provider=hosting_provider,
        )

        # Add to cache
        if domain not in self._snapshots:
            self._snapshots[domain] = []
        self._snapshots[domain].append(snapshot)

        # Keep only last 20 snapshots per domain
        if len(self._snapshots[domain]) > 20:
            self._snapshots[domain] = self._snapshots[domain][-20:]

        # Save to disk
        self._save_snapshots(domain)

        # Schedule rescans if this is initial scan
        if scan_reason == ScanReason.INITIAL:
            self._schedule_rescans(domain)

        logger.info(f"Added snapshot for {domain} (reason: {scan_reason.value})")
        return snapshot

    def _schedule_rescans(self, domain: str):
        """Schedule automatic rescans for a domain."""
        now = datetime.now(timezone.utc)

        if domain not in self._scheduled:
            self._scheduled[domain] = []

        for interval, reason in self.RESCAN_INTERVALS:
            scheduled_time = now + interval
            rescan = ScheduledRescan(
                domain=domain,
                scheduled_time=scheduled_time,
                reason=reason,
            )
            self._scheduled[domain].append(rescan)
            logger.debug(f"Scheduled {reason.value} for {domain} at {scheduled_time}")
        self._save_rescans()

    def cancel_rescans(self, domain: str) -> int:
        """Cancel all scheduled rescans for a domain."""
        rescans = self._scheduled.pop(domain, None)
        self._save_rescans()
        return len(rescans) if rescans else 0

    def get_due_rescans(self) -> list[ScheduledRescan]:
        """Get all rescans that are due now."""
        now = datetime.now(timezone.utc)
        due = []

        for domain, rescans in self._scheduled.items():
            for rescan in rescans:
                if rescan.scheduled_time <= now and rescan.attempts < rescan.max_attempts:
                    due.append(rescan)

        return due

    def mark_rescan_complete(self, domain: str, reason: ScanReason):
        """Mark a rescan as complete."""
        if domain in self._scheduled:
            self._scheduled[domain] = [
                r for r in self._scheduled[domain]
                if r.reason != reason
            ]
            self._save_rescans()

    def mark_rescan_failed(self, domain: str, reason: ScanReason):
        """Mark a rescan attempt as failed."""
        if domain in self._scheduled:
            for rescan in self._scheduled[domain]:
                if rescan.reason == reason:
                    rescan.attempts += 1
                    # Reschedule with backoff
                    rescan.scheduled_time = datetime.now(timezone.utc) + timedelta(
                        minutes=30 * rescan.attempts
                    )
            self._save_rescans()

    def analyze(self, domain: str) -> TemporalAnalysis:
        """Analyze temporal patterns for a domain."""
        analysis = TemporalAnalysis(domain=domain)

        snapshots = self._snapshots.get(domain, [])
        if not snapshots:
            return analysis

        analysis.snapshots_count = len(snapshots)
        analysis.first_seen = snapshots[0].timestamp
        analysis.last_seen = snapshots[-1].timestamp

        if len(snapshots) < 2:
            return analysis

        # Compare snapshots for changes
        scores = [s.score for s in snapshots]
        titles = set(s.title for s in snapshots if s.title)
        html_hashes = set(s.html_hash for s in snapshots if s.html_hash)

        # Content change detection
        analysis.content_changed = len(html_hashes) > 1
        analysis.title_changed = len(titles) > 1

        # Score changes
        if len(scores) >= 2:
            analysis.score_increased = scores[-1] > scores[0]
            analysis.score_decreased = scores[-1] < scores[0]

            # Calculate variance
            avg_score = sum(scores) / len(scores)
            variance = sum((s - avg_score) ** 2 for s in scores) / len(scores)
            analysis.score_variance = variance ** 0.5

        # Cloaking detection
        analysis.cloaking_detected, analysis.cloaking_confidence, analysis.cloaking_pattern = \
            self._detect_cloaking(snapshots)

        # Intermittent malicious behavior
        high_scores = sum(1 for s in scores if s >= 70)
        low_scores = sum(1 for s in scores if s < 40)
        if high_scores > 0 and low_scores > 0:
            analysis.intermittent_malicious = True

        # Different content at different times
        if len(html_hashes) > 1 or len(titles) > 1:
            analysis.shows_different_content = True

        # Calculate temporal risk
        analysis.calculate_risk()

        return analysis

    def _detect_cloaking(
        self,
        snapshots: list[DomainSnapshot]
    ) -> tuple[bool, float, str]:
        """Detect cloaking patterns from snapshots."""

        if len(snapshots) < 2:
            return False, 0.0, ""

        # Pattern 0: Seed form appears/disappears between scans (UI cloaking)
        # This is strong evidence of intentional evasion even if the overall score stays high.
        def has_seed_form(snapshot: DomainSnapshot) -> bool:
            for r in snapshot.reasons or []:
                rl = (r or "").lower()
                if "seed phrase form found" in rl:
                    return True
                if rl.startswith("explore:") and "seed form found" in rl:
                    return True
                if "seed form found" in rl:
                    return True
            return False

        seed_flags = [has_seed_form(s) for s in snapshots]
        if any(seed_flags) and not all(seed_flags):
            return True, 0.85, "seed_form_toggle"

        # Pattern 1: High score initially, then low (site detected scanner)
        if snapshots[0].score >= 70 and snapshots[-1].score < 40:
            return True, 0.8, "score_drop_after_detection"

        # Pattern 2: Content hash changes but title stays same (dynamic cloaking)
        html_hashes = [s.html_hash for s in snapshots if s.html_hash]
        titles = [s.title for s in snapshots if s.title]
        if len(set(html_hashes)) > 2 and len(set(titles)) == 1:
            return True, 0.7, "dynamic_content_same_title"

        # Pattern 3: Different verdicts over time
        verdicts = [s.verdict for s in snapshots]
        if "high" in verdicts and "low" in verdicts:
            return True, 0.9, "verdict_flip"

        # Pattern 4: Blocked requests vary significantly
        blocked = [s.blocked_requests for s in snapshots]
        if max(blocked) > 0 and min(blocked) == 0:
            return True, 0.6, "inconsistent_antibot"

        return False, 0.0, ""

    def get_snapshots(self, domain: str) -> list[DomainSnapshot]:
        """Get all snapshots for a domain."""
        return self._snapshots.get(domain, [])

    def get_latest_snapshot(self, domain: str) -> Optional[DomainSnapshot]:
        """Get the most recent snapshot for a domain."""
        snapshots = self._snapshots.get(domain, [])
        return snapshots[-1] if snapshots else None

    async def run_rescan_loop(self):
        """Background loop to process scheduled rescans."""
        while True:
            try:
                due_rescans = self.get_due_rescans()

                for rescan in due_rescans:
                    if self._rescan_callback:
                        try:
                            logger.info(f"Executing {rescan.reason.value} for {rescan.domain}")
                            await self._rescan_callback(rescan.domain, rescan.reason)
                            self.mark_rescan_complete(rescan.domain, rescan.reason)
                        except Exception as e:
                            logger.error(f"Rescan failed for {rescan.domain}: {e}")
                            self.mark_rescan_failed(rescan.domain, rescan.reason)
                        finally:
                            self._save_rescans()

                # Check every 5 minutes
                await asyncio.sleep(300)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Rescan loop error: {e}")
                await asyncio.sleep(60)

    def get_stats(self) -> dict:
        """Get temporal tracking statistics."""
        total_snapshots = sum(len(s) for s in self._snapshots.values())
        pending_rescans = sum(len(r) for r in self._scheduled.values())

        return {
            "domains_tracked": len(self._snapshots),
            "total_snapshots": total_snapshots,
            "pending_rescans": pending_rescans,
        }


# Convenience function
def create_temporal_tracker(data_dir: Path) -> TemporalTracker:
    """Create a temporal tracker with storage in data directory."""
    storage_dir = data_dir / "temporal"
    return TemporalTracker(storage_dir)
