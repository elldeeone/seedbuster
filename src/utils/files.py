"""Filesystem-safe naming helpers."""

from __future__ import annotations


def safe_filename_component(
    value: str,
    *,
    max_length: int | None = None,
    default: str = "unknown",
    lower: bool = False,
) -> str:
    """Convert a string into a filesystem-friendly filename component."""
    raw = (value or "").strip()
    if not raw:
        return default
    if lower:
        raw = raw.lower()
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in raw)
    if max_length:
        safe = safe[:max_length]
    return safe
