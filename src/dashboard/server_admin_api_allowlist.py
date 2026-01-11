"""Admin allowlist API handlers."""

from __future__ import annotations

from aiohttp import web

from ..utils.domains import normalize_allowlist_domain


class DashboardServerAdminApiAllowlistMixin:
    """Admin allowlist API."""

    async def _admin_api_allowlist(self, request: web.Request) -> web.Response:
        """Return allowlist entries."""
        self._require_csrf_header(request)
        entries = sorted(self._load_allowlist_entries(force=True))
        payload = [
            {"domain": entry, "locked": entry in self._allowlist_heuristics}
            for entry in entries
        ]
        return web.json_response({"entries": payload})

    async def _admin_api_allowlist_add(self, request: web.Request) -> web.Response:
        """Add a domain to the allowlist."""
        self._require_csrf_header(request)
        data = await self._read_json(request)
        raw_domain = str(data.get("domain") or "").strip()
        normalized = normalize_allowlist_domain(raw_domain)
        if not normalized:
            raise web.HTTPBadRequest(text="domain is required")

        file_entries = self._read_allowlist_entries()
        merged_entries = file_entries | self._allowlist_heuristics
        if normalized in merged_entries:
            updated = await self.database.apply_allowlist_entry(normalized)
            return web.json_response({"status": "exists", "domain": normalized, "updated_domains": updated})

        file_entries.add(normalized)
        self._write_allowlist_entries(file_entries)
        self._load_allowlist_entries(force=True)

        updated = await self.database.apply_allowlist_entry(normalized)
        await self.database.enqueue_dashboard_action(
            "allowlist_add",
            {"domain": normalized},
            target=normalized,
            dedupe=True,
        )
        return web.json_response({"status": "added", "domain": normalized, "updated_domains": updated})

    async def _admin_api_allowlist_remove(self, request: web.Request) -> web.Response:
        """Remove a domain from the allowlist."""
        self._require_csrf_header(request)
        data = await self._read_json(request)
        raw_domain = str(data.get("domain") or "").strip()
        normalized = normalize_allowlist_domain(raw_domain)
        if not normalized:
            raise web.HTTPBadRequest(text="domain is required")

        file_entries = self._read_allowlist_entries()
        if normalized in self._allowlist_heuristics:
            return web.json_response({"status": "locked", "domain": normalized})
        if normalized not in file_entries:
            return web.json_response({"status": "missing", "domain": normalized})

        file_entries.remove(normalized)
        self._write_allowlist_entries(file_entries)
        self._load_allowlist_entries(force=True)

        await self.database.enqueue_dashboard_action(
            "allowlist_remove",
            {"domain": normalized},
            target=normalized,
            dedupe=True,
        )
        return web.json_response({"status": "removed", "domain": normalized})
