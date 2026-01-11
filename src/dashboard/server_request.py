"""Request helper methods for dashboard server."""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

from aiohttp import web

from ..utils.domains import normalize_source_url


class DashboardServerRequestMixin:
    """Request helper utilities."""

    @staticmethod
    def _normalize_source_url(source_url: str | None, *, canonical: str | None = None) -> str | None:
        return normalize_source_url(source_url, canonical=canonical)

    @staticmethod
    def _is_root_source_url(source_url: str) -> bool:
        try:
            parsed = urlparse(source_url)
        except Exception:
            return False
        path = parsed.path or ""
        has_extra = bool(parsed.query or parsed.fragment)
        return path in ("", "/") and not has_extra

    def _client_ip(self, request: web.Request) -> str:
        """Best-effort client IP extraction (supports X-Forwarded-For)."""
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        remote = (request.remote or "").split(":")[0]
        return remote or "unknown"

    def _public_base_url(self, request: web.Request) -> str:
        proto = (request.headers.get("X-Forwarded-Proto") or request.scheme or "http").split(",")[0].strip()
        host = (
            request.headers.get("X-Forwarded-Host")
            or request.headers.get("Host")
            or request.host
            or ""
        )
        host = host.split(",")[0].strip()
        return f"{proto}://{host}"

    def _session_hash(self, request: web.Request) -> str:
        """Generate a stable, non-PII session hash for deduping."""
        raw = f"{self._client_ip(request)}:{request.headers.get('User-Agent', 'unknown')}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _is_disallowed_public_host(self, host: str) -> bool:
        """Block localhost/private/internal submissions."""
        candidate = (host or "").strip().lower().strip("[]")
        host_only = candidate.split(":", 1)[0] if ":" in candidate and candidate.count(":") == 1 else candidate
        try:
            ip_obj = ipaddress.ip_address(host_only)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_reserved
                or ip_obj.is_link_local
                or ip_obj.is_multicast
            ):
                return True
        except ValueError:
            pass

        if host_only in {"localhost", "local", "localhost.localdomain"}:
            return True
        if host_only.endswith((".local", ".internal", ".localhost")):
            return True
        return False

    def _rate_limit_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        """Simple sliding-window rate limiter keyed by arbitrary string (e.g., IP)."""
        now = datetime.now(timezone.utc).timestamp()
        window_start = now - float(window_seconds)
        entries = [t for t in self._public_rate_limits.get(key, []) if t >= window_start]
        if len(entries) >= limit:
            self._public_rate_limits[key] = entries
            return False
        entries.append(now)
        self._public_rate_limits[key] = entries
        return True

    def _cache_get(self, cache: dict[str, tuple[float, list[str]]], key: str) -> list[str] | None:
        now = datetime.now(timezone.utc).timestamp()
        entry = cache.get(key)
        if not entry:
            return None
        expires_at, values = entry
        if expires_at < now:
            cache.pop(key, None)
            return None
        return values

    def _cache_set(self, cache: dict[str, tuple[float, list[str]]], key: str, values: list[str]) -> None:
        expires_at = datetime.now(timezone.utc).timestamp() + float(self._cache_ttl_seconds)
        cache[key] = (expires_at, values)

    def _scams_cache_key(self, base_url: str) -> str:
        return base_url.rstrip("/")
