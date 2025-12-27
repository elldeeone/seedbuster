"""Temporal analysis service interface and utilities.

Provides a clean abstraction layer between the analysis pipeline and
temporal tracking implementation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Protocol


class ScanReason(str, Enum):
    """Reason for scanning a domain."""

    INITIAL = "initial"
    RESCAN_6H = "rescan_6h"
    RESCAN_24H = "rescan_24h"
    RESCAN_7D = "rescan_7d"
    MANUAL = "manual"
    WATCHLIST = "watchlist"
    CAMPAIGN = "campaign"


@dataclass
class SnapshotData:
    """Data for a domain analysis snapshot.

    Consolidates all the parameters needed to record a snapshot,
    reducing the coupling between pipeline and temporal tracker.
    """

    score: int
    verdict: str
    reasons: List[str] = field(default_factory=list)
    html_hash: Optional[str] = None
    form_hash: Optional[str] = None
    visual_hash: Optional[str] = None


@dataclass
class TemporalStatistics:
    """Statistics about a domain's temporal analysis history."""

    snapshot_count: int
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    score_trend: str = "stable"  # "increasing", "decreasing", "stable", "volatile"
    cloaking_detected: bool = False
    cloaking_confidence: float = 0.0


@dataclass
class TemporalInfo:
    """Formatted temporal information for alerts and reports.

    This is the consumer-facing format used by alert formatters,
    decoupled from the internal TemporalAnalysis representation.
    """

    is_initial_scan: bool
    scan_number: int
    total_scans: int
    rescans_scheduled: bool
    cloaking_suspected: bool = False
    cloaking_confirmed: bool = False
    cloaking_confidence: float = 0.0
    previous_score: Optional[int] = None
    score_delta: Optional[int] = None


class ITemporalService(Protocol):
    """Interface for temporal analysis operations.

    This protocol defines the contract between the analysis pipeline
    and temporal tracking implementation, allowing for easier testing
    and potential implementation swaps.
    """

    def add_snapshot(
        self,
        domain: str,
        snapshot: SnapshotData,
        scan_reason: ScanReason,
    ) -> None:
        """Record a domain analysis snapshot."""
        ...

    def analyze(self, domain: str) -> "TemporalAnalysis":
        """Analyze temporal patterns for a domain."""
        ...

    def get_statistics(self, domain: str) -> TemporalStatistics:
        """Get temporal statistics for a domain."""
        ...

    def schedule_rescan(
        self,
        domain: str,
        reason: ScanReason,
        delay_seconds: int,
    ) -> None:
        """Schedule a domain rescan."""
        ...


class TemporalFormatter:
    """Formats temporal analysis data for consumers.

    Encapsulates the logic for transforming internal TemporalAnalysis
    objects into the consumer-facing TemporalInfo format.
    """

    @staticmethod
    def format_for_alert(
        temporal_analysis: "TemporalAnalysis",
        snapshot_count: int,
        is_rescan: bool,
        previous_score: Optional[int] = None,
        current_score: Optional[int] = None,
    ) -> TemporalInfo:
        """Format temporal data for alert messages.

        Args:
            temporal_analysis: The raw temporal analysis result
            snapshot_count: Number of snapshots taken
            is_rescan: Whether this is a rescan (not initial)
            previous_score: Previous detection score (if available)
            current_score: Current detection score (for delta calculation)

        Returns:
            TemporalInfo ready for alert formatting
        """
        score_delta = None
        if previous_score is not None and current_score is not None:
            score_delta = current_score - previous_score

        return TemporalInfo(
            is_initial_scan=not is_rescan,
            scan_number=snapshot_count,
            total_scans=5,  # Default rescan count for initial scans
            rescans_scheduled=not is_rescan,
            cloaking_suspected=temporal_analysis.temporal_risk_score > 20,
            cloaking_confirmed=temporal_analysis.cloaking_detected,
            cloaking_confidence=temporal_analysis.cloaking_confidence,
            previous_score=previous_score,
            score_delta=score_delta,
        )

    @staticmethod
    def get_scan_label(scan_reason: ScanReason, snapshot_count: int) -> str:
        """Get human-readable label for a scan.

        Args:
            scan_reason: The reason for the scan
            snapshot_count: Number of snapshots including this one

        Returns:
            Label like "Initial scan", "Rescan 2/5", etc.
        """
        if scan_reason == ScanReason.INITIAL:
            return "Initial scan"
        elif scan_reason == ScanReason.MANUAL:
            return "Manual rescan"
        elif scan_reason == ScanReason.WATCHLIST:
            return "Watchlist check"
        elif scan_reason == ScanReason.CAMPAIGN:
            return "Campaign scan"
        else:
            # Automated rescan
            return f"Rescan {snapshot_count}/5"

    @staticmethod
    def should_include_temporal_context(
        temporal_analysis: "TemporalAnalysis",
        is_rescan: bool,
    ) -> bool:
        """Determine if temporal context should be included in reports.

        Returns True if there's meaningful temporal information to show
        (cloaking, score changes, etc.)
        """
        if not is_rescan:
            return False

        # Include if cloaking detected or suspected
        if temporal_analysis.cloaking_detected:
            return True
        if temporal_analysis.cloaking_confidence > 30:
            return True

        # Include if there are temporal-specific reasons
        if temporal_analysis.temporal_reasons:
            return True

        return False


# Import for type hints only (avoid circular imports)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .temporal import TemporalAnalysis
