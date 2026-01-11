"""Telegram allowlist helpers."""

from __future__ import annotations

import logging

from ..utils.allowlist import read_allowlist, write_allowlist
from ..utils.domains import normalize_allowlist_domain

logger = logging.getLogger(__name__)


class TelegramAllowlistMixin:
    """Allowlist file helpers."""

    def _read_allowlist_entries(self) -> set[str]:
        """Read allowlist entries from disk."""
        path = self.allowlist_path
        if not path.exists():
            return set()

        return read_allowlist(path)

    def _write_allowlist_entries(self, entries: set[str]) -> None:
        """Write allowlist entries to disk (sorted, atomic)."""
        path = self.allowlist_path
        path.parent.mkdir(parents=True, exist_ok=True)

        write_allowlist(path, entries)

    def _add_allowlist_entry(self, domain: str) -> bool:
        """Add a domain to the allowlist file and sync callbacks."""
        normalized = normalize_allowlist_domain(domain)
        if not normalized:
            return False

        entries = self._read_allowlist_entries()
        if normalized in entries:
            return False

        entries.add(normalized)
        self._write_allowlist_entries(entries)

        if self._allowlist_add_callback:
            try:
                self._allowlist_add_callback(normalized)
            except Exception as exc:
                logger.warning("Allowlist add callback failed for %s: %s", normalized, exc)

        return True

    def _remove_allowlist_entry(self, domain: str) -> bool:
        """Remove a domain from the allowlist file and sync callbacks."""
        normalized = normalize_allowlist_domain(domain)
        if not normalized:
            return False

        entries = self._read_allowlist_entries()
        if normalized not in entries:
            return False

        entries.remove(normalized)
        self._write_allowlist_entries(entries)

        if self._allowlist_remove_callback:
            try:
                self._allowlist_remove_callback(normalized)
            except Exception as exc:
                logger.warning("Allowlist remove callback failed for %s: %s", normalized, exc)

        return True
