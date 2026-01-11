"""Detection metrics tracking for pattern analysis.

Provides insight into which patterns are triggering and how often,
enabling data-driven tuning of detection thresholds and patterns.
"""

import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class PatternMetrics:
    """Metrics for a single pattern."""

    hits: int = 0
    last_hit: Optional[datetime] = None
    domains: set = field(default_factory=set)

    def record_hit(self, domain: str) -> None:
        self.hits += 1
        self.last_hit = datetime.now()
        self.domains.add(domain)


@dataclass
class CategoryMetrics:
    """Metrics for a pattern category."""

    detections: int = 0  # Times threshold was met
    total_hits: int = 0  # Total pattern matches
    last_detection: Optional[datetime] = None
    domains: set = field(default_factory=set)
    pattern_hits: dict = field(default_factory=lambda: defaultdict(PatternMetrics))

    def record_pattern_hit(self, pattern: str, domain: str) -> None:
        self.total_hits += 1
        if pattern not in self.pattern_hits:
            self.pattern_hits[pattern] = PatternMetrics()
        self.pattern_hits[pattern].record_hit(domain)

    def record_detection(self, domain: str) -> None:
        self.detections += 1
        self.last_detection = datetime.now()
        self.domains.add(domain)


class DetectionMetrics:
    """Thread-safe metrics collector for detection analysis.

    Tracks pattern matches, category detections, and scam type distributions.
    """

    _instance: Optional["DetectionMetrics"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "DetectionMetrics":
        """Singleton pattern for global metrics access."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if self._initialized:
            return
        self._initialized = True
        self._lock = threading.Lock()
        self._categories: dict[str, CategoryMetrics] = defaultdict(CategoryMetrics)
        self._scam_types: dict[str, int] = defaultdict(int)
        self._verdicts: dict[str, int] = defaultdict(int)
        self._total_analyses: int = 0
        self._started: datetime = datetime.now()

    def record_pattern_hit(
        self, category: str, pattern: str, domain: str
    ) -> None:
        """Record a pattern match."""
        with self._lock:
            self._categories[category].record_pattern_hit(pattern, domain)

    def record_category_detection(self, category: str, domain: str) -> None:
        """Record when a category threshold is met."""
        with self._lock:
            self._categories[category].record_detection(domain)

    def record_scam_type(self, scam_type: str) -> None:
        """Record a scam type detection."""
        with self._lock:
            self._scam_types[scam_type] += 1

    def record_verdict(self, verdict: str) -> None:
        """Record a verdict classification."""
        with self._lock:
            self._verdicts[verdict] += 1
            self._total_analyses += 1

    def get_summary(self) -> dict:
        """Get a summary of all metrics."""
        with self._lock:
            uptime = datetime.now() - self._started
            return {
                "uptime_seconds": int(uptime.total_seconds()),
                "total_analyses": self._total_analyses,
                "verdicts": dict(self._verdicts),
                "scam_types": dict(self._scam_types),
                "categories": {
                    name: {
                        "detections": cat.detections,
                        "total_hits": cat.total_hits,
                        "unique_domains": len(cat.domains),
                        "last_detection": (
                            cat.last_detection.isoformat()
                            if cat.last_detection
                            else None
                        ),
                        "top_patterns": self._get_top_patterns(cat, 5),
                    }
                    for name, cat in self._categories.items()
                },
            }

    def _get_top_patterns(
        self, category: CategoryMetrics, n: int
    ) -> list[dict]:
        """Get top N patterns by hit count."""
        sorted_patterns = sorted(
            category.pattern_hits.items(),
            key=lambda x: x[1].hits,
            reverse=True,
        )[:n]
        return [
            {"pattern": p[:50], "hits": m.hits}
            for p, m in sorted_patterns
        ]

    def reset(self) -> None:
        """Reset all metrics (useful for testing)."""
        with self._lock:
            self._categories.clear()
            self._scam_types.clear()
            self._verdicts.clear()
            self._total_analyses = 0
            self._started = datetime.now()


# Global instance
metrics = DetectionMetrics()
