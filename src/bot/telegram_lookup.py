"""Telegram lookup helpers."""

from __future__ import annotations

from typing import Optional


class TelegramLookupMixin:
    """Lookup helpers."""

    async def _find_domain_by_short_id(self, identifier: str) -> Optional[dict]:
        """Find a domain by ID, domain name, or short hash prefix."""
        domains = await self.database.get_recent_domains(limit=100)

        for d in domains:
            if d["domain"].lower() == identifier.lower():
                return d

        if identifier.isdigit():
            for d in domains:
                if str(d["id"]) == identifier:
                    return d

        for d in domains:
            if self.evidence_store.get_domain_id(d["domain"]).startswith(identifier):
                return d

        for d in domains:
            if identifier.lower() in d["domain"].lower():
                return d

        return None
