"""Security and CSRF helpers for dashboard server."""

from __future__ import annotations

import base64
import secrets

from aiohttp import web

from .server_helpers import EVIDENCE_HTML_CSP


class DashboardServerSecurityMixin:
    """Auth + CSRF helpers."""

    @web.middleware
    async def _admin_auth_middleware(self, request: web.Request, handler):  # type: ignore[override]
        path = request.path or ""
        if not path.startswith("/admin"):
            return await handler(request)

        if (
            path.startswith("/admin/assets")
            or path.startswith("/admin/manifest")
            or path.startswith("/admin/favicon")
            or path.startswith("/admin/.well-known")
        ):
            return await handler(request)

        if not self.config.admin_password:
            raise web.HTTPForbidden(text="Admin dashboard not configured (set DASHBOARD_ADMIN_PASSWORD).")

        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="SeedBuster Admin"'},
                text="Authentication required.",
            )

        try:
            raw = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
            user, password = raw.split(":", 1)
        except Exception:
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="SeedBuster Admin"'},
                text="Invalid Authorization header.",
            )

        if user != self.config.admin_user or password != self.config.admin_password:
            raise web.HTTPUnauthorized(
                headers={"WWW-Authenticate": 'Basic realm="SeedBuster Admin"'},
                text="Invalid credentials.",
            )

        return await handler(request)

    @web.middleware
    async def _evidence_sandbox_middleware(self, request: web.Request, handler):  # type: ignore[override]
        response = await handler(request)
        path = (request.path or "").lower()
        if path.startswith("/evidence"):
            response.headers["Cache-Control"] = "no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
            if path.endswith((".html", ".htm")):
                response.headers["Content-Security-Policy"] = EVIDENCE_HTML_CSP
                response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def _get_or_set_csrf(self, request: web.Request, response: web.StreamResponse) -> str:
        name = "sb_admin_csrf"
        token = (request.cookies.get(name) or "").strip()
        if not token:
            token = secrets.token_urlsafe(32)
            response.set_cookie(
                name,
                token,
                path="/admin",
                httponly=True,
                samesite="Strict",
                secure=(request.url.scheme == "https"),
            )
        return token

    async def _require_csrf(self, request: web.Request) -> web.MultiDictProxy:
        name = "sb_admin_csrf"
        cookie = (request.cookies.get(name) or "").strip()
        data = await request.post()
        sent = (data.get("csrf") or "").strip()
        if not cookie or not sent or sent != cookie:
            raise web.HTTPForbidden(text="CSRF check failed.")
        return data

    def _require_csrf_header(self, request: web.Request) -> None:
        name = "sb_admin_csrf"
        cookie = (request.cookies.get(name) or "").strip()
        sent = (request.headers.get("X-CSRF-Token") or "").strip()
        if not cookie or not sent or sent != cookie:
            raise web.HTTPForbidden(text="CSRF check failed.")

    async def _read_json(self, request: web.Request, *, allow_empty: bool = False) -> dict:
        if allow_empty:
            if not request.can_read_body or request.content_length in (None, 0):
                return {}
        try:
            data = await request.json()
        except Exception:
            raise web.HTTPBadRequest(text="Invalid JSON payload")
        if not isinstance(data, dict):
            raise web.HTTPBadRequest(text="Invalid JSON payload")
        return data
