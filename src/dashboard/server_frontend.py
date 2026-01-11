"""Frontend asset handler for dashboard server."""

from __future__ import annotations

from aiohttp import web


class DashboardServerFrontendMixin:
    """Serve SPA frontend assets."""

    async def _serve_frontend(self, request: web.Request) -> web.Response:
        """Serve built SPA assets for the admin dashboard."""
        index_path = self.frontend_dir / "index.html"
        if not index_path.exists():
            raise web.HTTPNotFound(text="Frontend not built (run npm run build in frontend/)")
        try:
            html_out = index_path.read_text(encoding="utf-8")
        except Exception:
            raise web.HTTPInternalServerError(text="Failed to read frontend bundle.")

        mode = "admin" if (request.path or "").startswith("/admin") else "public"
        response = web.Response(
            text=html_out,
            content_type="text/html",
            headers={"Cache-Control": "no-cache"},
        )
        csrf_token = ""
        if mode == "admin":
            csrf_token = self._get_or_set_csrf(request, response)
        csrf_fragment = f";window.__SB_CSRF=\"{csrf_token}\"" if csrf_token else ""
        mode_script = f"<script>window.__SB_MODE=\"{mode}\"{csrf_fragment};</script>"
        if "</head>" in html_out:
            html_out = html_out.replace("</head>", f"{mode_script}</head>", 1)
        else:
            html_out = mode_script + html_out

        response.text = html_out
        return response
