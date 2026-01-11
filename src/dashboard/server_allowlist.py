"""Allowlist helpers for the dashboard server."""

from __future__ import annotations

import time

import tldextract

from ..utils.allowlist import read_allowlist, write_allowlist
from ..utils.domains import allowlist_contains, canonicalize_domain
from .server_helpers import _extract_hostname


class DashboardServerAllowlistMixin:
    """Allowlist helpers."""

    def _read_allowlist_entries(self) -> set[str]:
        """Read allowlist entries from disk (best-effort)."""
        path = self._allowlist_path
        if not path or not path.exists():
            return set()

        return read_allowlist(path)

    def _write_allowlist_entries(self, entries: set[str]) -> None:
        """Write allowlist entries to disk (sorted, atomic)."""
        path = self._allowlist_path
        if not path:
            raise RuntimeError("allowlist_path is not configured")

        path.parent.mkdir(parents=True, exist_ok=True)
        write_allowlist(path, entries)

    def _load_allowlist_entries(self, *, force: bool = False) -> set[str]:
        """Load allowlist entries with a small cache window."""
        if not self._allowlist_path:
            return self._allowlist

        now = time.time()
        if (
            not force
            and self._allowlist_loaded_at is not None
            and (now - self._allowlist_loaded_at) < self._allowlist_reload_seconds
        ):
            return self._allowlist

        file_entries = self._read_allowlist_entries()
        self._allowlist_file_entries = file_entries
        self._allowlist = file_entries | self._allowlist_heuristics
        self._allowlist_loaded_at = now
        return self._allowlist

    def _normalize_domain_key(self, domain: str) -> str:
        """Normalize a domain for lookups (strip scheme/path, lowercase)."""
        return canonicalize_domain(domain) or _extract_hostname(domain)

    def _registered_domain(self, domain: str) -> str:
        """Return the registered domain (second-level + suffix) for allowlist checks."""
        host = self._normalize_domain_key(domain)
        if not host:
            return ""
        extracted = tldextract.extract(host)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()
        return host

    def _is_allowlisted_domain(self, domain: str) -> bool:
        """Return True if the domain (or its registered form) is allowlisted."""
        allowlist = self._load_allowlist_entries()
        return allowlist_contains(domain, allowlist)
