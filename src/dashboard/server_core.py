"""Core dashboard server initialization and lifecycle."""

from __future__ import annotations

import asyncio
import inspect
import os
from pathlib import Path
from typing import Callable, Optional

import aiohttp
from aiohttp import web

from ..storage.database import Database
from .server_config import DashboardConfig
from .server_helpers import SCAMS_CACHE_TTL_SECONDS


class DashboardServerCoreMixin:
    """Core dashboard server lifecycle."""

    def __init__(
        self,
        *,
        config: DashboardConfig,
        database: Database,
        evidence_dir: Path,
        campaigns_dir: Path | None = None,
        submit_callback: Callable[[str, str | None], None] | None = None,
        rescan_callback: Callable[[str], None] | None = None,
        report_callback: Callable[[int, str, Optional[list[str]], bool], object] | None = None,
        mark_manual_done_callback: Callable[[int, str, Optional[list[str]], str], object] | None = None,
        get_available_platforms: Callable[[], list[str]] | None = None,
        get_platform_info: Callable[[], dict[str, dict]] | None = None,
        get_manual_report_options: Callable[[int, str, Optional[list[str]]], object] | None = None,
        generate_domain_pdf_callback: Callable[[str, int | None, str | None], Path | None] | None = None,
        generate_domain_package_callback: Callable[[str, int | None, str | None], Path | None] | None = None,
        preview_domain_report_callback: Callable[[int, str], dict] | None = None,
        generate_campaign_pdf_callback: Callable[[str], Path | None] | None = None,
        generate_campaign_package_callback: Callable[[str], Path | None] | None = None,
        preview_campaign_report_callback: Callable[[str], dict] | None = None,
        submit_campaign_report_callback: Callable[[str], dict] | None = None,
    ):
        self.config = config
        self.database = database
        self._allowlist_path = getattr(config, "allowlist_path", None)
        self._allowlist_config = {d.lower() for d in getattr(config, "allowlist", [])}
        self._allowlist_file_entries: set[str] = set()
        self._allowlist_heuristics = set(self._allowlist_config)
        if self._allowlist_path and self._allowlist_path.exists():
            file_entries = self._read_allowlist_entries()
            self._allowlist_file_entries = file_entries
        self._allowlist = self._allowlist_file_entries | self._allowlist_heuristics
        self._allowlist_loaded_at: float | None = None
        self._allowlist_reload_seconds = 5.0
        self.evidence_dir = evidence_dir
        self.campaigns_dir = campaigns_dir
        self.frontend_dir = Path(
            config.frontend_dir
            or os.environ.get("DASHBOARD_FRONTEND_DIST")
            or Path(__file__).parent / "frontend" / "dist"
        )
        self._frontend_available = (self.frontend_dir / "index.html").exists()
        self.submit_callback = submit_callback
        self.rescan_callback = rescan_callback
        self.report_callback = report_callback
        self.mark_manual_done_callback = mark_manual_done_callback
        self.get_available_platforms = get_available_platforms or (lambda: [])
        self.get_platform_info = get_platform_info or (lambda: {})
        self.get_manual_report_options = get_manual_report_options
        self.generate_domain_pdf_callback = generate_domain_pdf_callback
        self.generate_domain_package_callback = generate_domain_package_callback
        self.preview_domain_report_callback = preview_domain_report_callback
        self.generate_campaign_pdf_callback = generate_campaign_pdf_callback
        self.generate_campaign_package_callback = generate_campaign_package_callback
        self.preview_campaign_report_callback = preview_campaign_report_callback
        self.submit_campaign_report_callback = submit_campaign_report_callback

        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None
        self._public_rate_limits: dict[str, list[float]] = {}
        self._dns_cache: dict[str, tuple[float, list[str]]] = {}
        self._ns_cache: dict[str, tuple[float, list[str]]] = {}
        self._cache_ttl_seconds = 600
        self._http_session: aiohttp.ClientSession | None = None
        self._scams_cache: dict[str, dict] = {}
        self._scams_cache_lock = asyncio.Lock()
        self._scams_cache_ttl_seconds = SCAMS_CACHE_TTL_SECONDS
        self._stats_cache: dict[str, tuple[float, dict]] = {}
        self._stats_cache_ttl_seconds = 15.0

        self._app = web.Application(
            middlewares=[
                self._admin_auth_middleware,
                self._evidence_sandbox_middleware,
            ]
        )
        self._register_routes()

    async def start(self) -> None:
        if not self.config.enabled:
            return
        if self._runner:
            return
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host=self.config.host, port=int(self.config.port))
        await self._site.start()

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        self._runner = None
        self._site = None
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()
        self._http_session = None

    async def _healthz(self, request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    def _invoke_submit_callback(self, domain: str, source_url: str | None) -> None:
        if not self.submit_callback:
            return
        try:
            signature = inspect.signature(self.submit_callback)
        except (TypeError, ValueError):
            self.submit_callback(domain, source_url)
            return

        params = list(signature.parameters.values())
        if any(p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD) for p in params):
            self.submit_callback(domain, source_url)
        elif len(params) <= 1:
            self.submit_callback(domain)
        else:
            self.submit_callback(domain, source_url)
