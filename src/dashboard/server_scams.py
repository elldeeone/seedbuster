"""Scams export helpers for dashboard server."""

from __future__ import annotations

import hashlib
import json
import time

import aiohttp
from aiohttp import web


class DashboardServerScamsMixin:
    """Scams export helpers."""

    async def _get_scams_cache(self, base_url: str) -> dict:
        key = self._scams_cache_key(base_url)
        now = time.time()
        cached = self._scams_cache.get(key)
        if cached and cached["expires_at"] > now:
            return cached

        async with self._scams_cache_lock:
            cached = self._scams_cache.get(key)
            now = time.time()
            if cached and cached["expires_at"] > now:
                return cached

            entry = await self._build_scams_cache_entry(base_url)
            self._scams_cache[key] = entry
            return entry

    async def _build_scams_cache_entry(self, base_url: str) -> dict:
        rows = await self.database.list_scams_for_export()
        scams = []
        for row in rows:
            domain = str(row.get("domain") or "").strip()
            if not domain:
                continue
            first_seen = self._format_iso_timestamp(row.get("first_seen")) or self._format_iso_timestamp(
                row.get("created_at")
            )
            domain_id = row.get("id")
            detail_url = f"{base_url}/#/domains/{domain_id}" if domain_id else f"{base_url}/#/domains"
            scams.append(
                {
                    "domain": domain,
                    "url": f"https://{domain}",
                    "first_seen": first_seen,
                    "scam_type": row.get("scam_type"),
                    "source": row.get("source"),
                    "detail_url": detail_url,
                }
            )

        payload = json.dumps(scams, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        etag = hashlib.sha256(payload).hexdigest()
        now = time.time()
        return {
            "payload": payload,
            "etag": f"\"{etag}\"",
            "generated_at": now,
            "expires_at": now + float(self._scams_cache_ttl_seconds),
        }

    async def _get_http_session(self) -> aiohttp.ClientSession:
        if self._http_session and not self._http_session.closed:
            return self._http_session
        timeout = aiohttp.ClientTimeout(total=5)
        self._http_session = aiohttp.ClientSession(timeout=timeout)
        return self._http_session

    def _scams_cors_headers(self) -> dict[str, str]:
        return {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        }

    def _scams_response_headers(self, etag: str) -> dict[str, str]:
        headers = self._scams_cors_headers()
        headers["Cache-Control"] = f"public, max-age={int(self._scams_cache_ttl_seconds)}"
        headers["ETag"] = etag
        return headers

    async def _public_api_scams_json(self, request: web.Request) -> web.Response:
        base_url = self._public_base_url(request)
        cache = await self._get_scams_cache(base_url)
        headers = self._scams_response_headers(cache["etag"])

        if_none_match = request.headers.get("If-None-Match", "")
        if if_none_match:
            tags = [tag.strip() for tag in if_none_match.split(",") if tag.strip()]
            if cache["etag"] in tags or cache["etag"].strip("\"") in tags:
                return web.Response(status=304, headers=headers)

        return web.Response(body=cache["payload"], content_type="application/json", headers=headers)

    async def _public_api_scams_options(self, _request: web.Request) -> web.Response:
        headers = self._scams_cors_headers()
        headers["Access-Control-Max-Age"] = str(int(self._scams_cache_ttl_seconds))
        headers["Cache-Control"] = f"public, max-age={int(self._scams_cache_ttl_seconds)}"
        return web.Response(status=204, headers=headers)
