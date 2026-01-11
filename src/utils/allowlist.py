"""Allowlist file helpers."""

from __future__ import annotations

from pathlib import Path

from .domains import normalize_allowlist_domain


def read_allowlist(path: Path) -> set[str]:
    """Read allowlist entries from disk (sorted, normalized)."""
    if not path.exists():
        return set()

    entries: set[str] = set()
    for line in path.read_text().splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        normalized = normalize_allowlist_domain(value)
        if normalized:
            entries.add(normalized)
    return entries


def write_allowlist(path: Path, entries: set[str]) -> None:
    """Write allowlist entries to disk (sorted, atomic)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    header = [
        "# Allowed domains (one per line)",
        "# These will never trigger alerts",
    ]
    content = "\n".join(header + sorted(entries) + [""])
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(content)
    tmp_path.replace(path)
