"""Centralized constants for SeedBuster.

This module contains enums and constants used across multiple modules
to ensure consistency and reduce duplication.
"""

from enum import IntEnum


class Verdict(IntEnum):
    """Verdict severity levels with ranking for comparison."""

    BENIGN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def from_string(cls, value: str | None) -> "Verdict":
        """Convert string verdict to enum, defaulting to BENIGN."""
        if not value:
            return cls.BENIGN
        mapping = {
            "benign": cls.BENIGN,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
        }
        return mapping.get(value.lower(), cls.BENIGN)

    def __str__(self) -> str:
        return self.name.lower()


class Status(IntEnum):
    """Domain status levels with ranking for comparison."""

    UNKNOWN = 0
    ANALYZING = 1
    ALLOWLISTED = 2
    FALSE_POSITIVE = 2
    PENDING = 2
    WATCHLIST = 3
    ANALYZED = 4
    REPORTED = 5

    @classmethod
    def from_string(cls, value: str | None) -> "Status":
        """Convert string status to enum, defaulting to UNKNOWN."""
        if not value:
            return cls.UNKNOWN
        mapping = {
            "analyzing": cls.ANALYZING,
            "allowlisted": cls.ALLOWLISTED,
            "false_positive": cls.FALSE_POSITIVE,
            "pending": cls.PENDING,
            "watchlist": cls.WATCHLIST,
            "analyzed": cls.ANALYZED,
            "reported": cls.REPORTED,
        }
        return mapping.get(value.lower(), cls.UNKNOWN)

    def __str__(self) -> str:
        return self.name.lower()


# Legacy dict format for backward compatibility
VERDICT_RANK = {v.name.lower(): v.value for v in Verdict}
VERDICT_RANK[None] = 0
VERDICT_RANK[""] = 0

# Build STATUS_RANK with all status values (some share ranks)
STATUS_RANK = {
    "reported": 5,
    "analyzed": 4,
    "watchlist": 3,
    "pending": 2,
    "allowlisted": 2,
    "false_positive": 2,
    "analyzing": 1,
    None: 0,
    "": 0,
}

# Convenience function for verdict comparison
def compare_verdicts(v1: str | None, v2: str | None) -> int:
    """Compare two verdict strings. Returns positive if v1 > v2, negative if v1 < v2, 0 if equal."""
    return Verdict.from_string(v1) - Verdict.from_string(v2)


def verdict_escalated(current: str | None, previous: str | None) -> bool:
    """Check if verdict has escalated (gotten worse)."""
    return compare_verdicts(current, previous) > 0
