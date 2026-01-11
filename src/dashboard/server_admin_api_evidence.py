"""Admin evidence API handlers."""

from __future__ import annotations

from aiohttp import web

from .server_helpers import _domain_dir_name


class DashboardServerAdminApiEvidenceMixin:
    """Admin evidence APIs."""

    async def _admin_api_evidence(self, request: web.Request) -> web.Response:
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")
        row = await self.database.get_domain_by_id(domain_id)
        if not row:
            raise web.HTTPNotFound(text="Domain not found")

        domain_dir = self.evidence_dir / _domain_dir_name(row["domain"])
        files: list[dict] = []
        if domain_dir.exists():
            for p in sorted(domain_dir.glob("**/*")):
                if p.is_file():
                    files.append({
                        "path": f"/evidence/{_domain_dir_name(row['domain'])}/{p.relative_to(domain_dir)}",
                        "size": p.stat().st_size,
                    })
        return web.json_response({"files": files})
