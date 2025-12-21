"""Minimal health/metrics server for SeedBuster."""

from __future__ import annotations

import logging
from typing import Callable

from aiohttp import web

logger = logging.getLogger(__name__)


class HealthServer:
    """Serves lightweight health and metrics endpoints."""

    def __init__(
        self,
        host: str,
        port: int,
        status_provider: Callable[[], dict],
        enabled: bool = True,
    ):
        self.host = host
        self.port = port
        self.status_provider = status_provider
        self.enabled = enabled
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    async def start(self):
        """Start the health server."""
        if not self.enabled:
            logger.info("Health server disabled")
            return

        app = web.Application()
        app.router.add_get("/healthz", self._handle_health)
        app.router.add_get("/metrics", self._handle_metrics)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.host, self.port)
        await self._site.start()
        logger.info("Health server listening on %s:%s", self.host, self.port)

    async def stop(self):
        """Stop the health server."""
        if self._site:
            await self._site.stop()
        if self._runner:
            await self._runner.cleanup()
        self._runner = None
        self._site = None

    async def _handle_health(self, request):  # noqa: ANN001
        """Return JSON health status."""
        try:
            payload = self.status_provider() or {}
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Health status provider failed: %s", exc)
            payload = {"status": "error", "message": str(exc)}

        # Basic readiness flag
        payload.setdefault("status", "ok")
        return web.json_response(payload, headers={"Access-Control-Allow-Origin": "*"})

    async def _handle_metrics(self, request):  # noqa: ANN001
        """Expose a handful of text metrics (Prometheus-ish)."""
        try:
            data = self.status_provider() or {}
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Metrics provider failed: %s", exc)
            data = {"status": "error", "message": str(exc)}

        lines = []
        for key, value in data.items():
            metric_key = str(key).replace(".", "_").replace("-", "_")
            if isinstance(value, (int, float)):
                lines.append(f"seedbuster_{metric_key} {value}")
            else:
                # Non-numeric fields are skipped to keep endpoint simple
                continue
        if not lines:
            lines.append('seedbuster_status{state="empty"} 1')

        return web.Response(text="\n".join(lines) + "\n")
