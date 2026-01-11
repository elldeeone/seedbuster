"""Status/verdict ranking helpers for comparisons."""

from __future__ import annotations

VERDICT_RANK = {
    "benign": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    None: 0,
    "": 0,
}

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


def compare_verdicts(v1: str | None, v2: str | None) -> int:
    """Compare two verdict strings. Positive if v1 > v2, negative if v1 < v2, 0 if equal."""
    return VERDICT_RANK.get((v1 or "").lower(), 0) - VERDICT_RANK.get((v2 or "").lower(), 0)


def verdict_escalated(current: str | None, previous: str | None) -> bool:
    """Check if verdict has escalated (gotten worse)."""
    return compare_verdicts(current, previous) > 0
