"""Public API handlers."""

from __future__ import annotations

from aiohttp import web

from ..utils.domains import canonicalize_domain, normalize_source_url
from .server_helpers import (
    _candidate_parent_domains,
    _coerce_int,
    _existing_submission_message,
    _extract_hostname,
)


class DashboardServerPublicApiMixin:
    """Public API handlers."""

    async def _public_api_submit(self, request: web.Request) -> web.Response:
        """Public endpoint to submit a suspicious domain for review."""
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON payload"}, status=400)

        honeypot = (data.get("hp") or data.get("honeypot") or "").strip()
        if honeypot:
            return web.json_response({"status": "submitted", "message": "Thank you"})

        target = (data.get("domain") or data.get("target") or "").strip()
        if not target:
            return web.json_response({"error": "domain is required"}, status=400)

        domain = canonicalize_domain(target) or _extract_hostname(target)
        canonical = canonicalize_domain(domain)
        if not canonical:
            return web.json_response({"error": "Invalid domain/URL"}, status=400)

        if self._is_disallowed_public_host(canonical):
            return web.json_response({"error": "Local/private hosts are not allowed"}, status=400)

        client_ip = self._client_ip(request)
        if not self._rate_limit_allowed(client_ip, limit=10, window_seconds=3600):
            return web.json_response(
                {"error": "Too many submissions. Please try again later."},
                status=429,
            )

        existing = None
        candidates = [canonical, *_candidate_parent_domains(canonical)]
        seen: set[str] = set()
        for candidate in candidates:
            candidate_key = (candidate or "").strip().lower()
            if not candidate_key or candidate_key in seen:
                continue
            seen.add(candidate_key)
            record = await self.database.get_domain_by_canonical(candidate_key)
            if record:
                existing = record
                break

        if existing:
            existing_domain = str(existing.get("domain") or canonical).strip()
            return web.json_response(
                {
                    "status": "already_tracked",
                    "domain": canonical,
                    "existing_domain": existing_domain,
                    "existing_domain_id": existing.get("id"),
                    "message": _existing_submission_message(existing),
                }
            )

        submitted_url = None
        if "/" in target or target.startswith(("http://", "https://")):
            submitted_url = normalize_source_url(target)
        source_url = normalize_source_url(data.get("source_url"))
        if source_url and len(source_url) > 2048:
            return web.json_response({"error": "Source URL too long"}, status=400)
        if submitted_url and len(submitted_url) > 2048:
            return web.json_response({"error": "Submitted URL too long"}, status=400)
        reporter_notes = (data.get("notes") or "").strip()
        if reporter_notes and len(reporter_notes) > 1000:
            reporter_notes = reporter_notes[:1000]

        submission_id, duplicate = await self.database.add_public_submission(
            domain=canonical,
            canonical_domain=canonical,
            source_url=source_url,
            submitted_url=submitted_url,
            reporter_notes=reporter_notes or None,
        )

        message = (
            "Thank you for your submission. It will be reviewed by our team."
            if not duplicate
            else "This domain was already submitted. We've updated the count."
        )

        return web.json_response(
            {
                "status": "submitted",
                "domain": canonical,
                "submission_id": submission_id,
                "duplicate": duplicate,
                "message": message,
            }
        )

    async def _public_api_report_options(self, request: web.Request) -> web.Response:
        """Return manual report options + counters for a domain."""
        domain_id = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        domain = await self.database.get_domain_by_id(domain_id)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found")
        takedown_status = str(domain.get("takedown_status") or "").strip().lower()
        if takedown_status == "confirmed_down":
            return web.json_response(
                {"error": "Domain marked as taken down; reporting is paused."},
                status=409,
            )

        platform_info = self.get_platform_info()
        available_platforms = self.get_available_platforms()
        if not available_platforms:
            return web.json_response({"error": "No reporting platforms configured"}, status=503)

        manual_data: dict[str, dict] = {}
        if self.get_manual_report_options:
            try:
                manual_data = await self.get_manual_report_options(
                    domain_id,
                    domain.get("domain", ""),
                    available_platforms,
                    public=True,
                )
            except Exception as exc:
                raise web.HTTPServiceUnavailable(text=f"Manual instructions unavailable: {exc}")
        else:
            raise web.HTTPServiceUnavailable(text="Manual instructions not configured")

        engagement_counts = await self.database.get_report_engagement_counts(domain_id)
        total_engagements = sum(engagement_counts.get(p, 0) for p in manual_data.keys())

        entries = []
        for platform in manual_data.keys():
            info = platform_info.get(platform, {}) if isinstance(platform_info, dict) else {}
            raw_instruction = manual_data.get(platform)
            instructions = None
            error = None
            if isinstance(raw_instruction, dict):
                if set(raw_instruction.keys()) == {"error"}:
                    error = str(raw_instruction.get("error"))
                else:
                    instructions = raw_instruction
            entries.append(
                {
                    "id": platform,
                    "name": info.get("name") or " ".join(part.capitalize() for part in platform.split("_")),
                    "manual_only": bool(info.get("manual_only", True)),
                    "url": info.get("url", ""),
                    "engagement_count": engagement_counts.get(platform, 0),
                    "instructions": instructions,
                    "error": error,
                }
            )

        return web.json_response(
            {
                "domain": domain.get("domain"),
                "domain_id": domain_id,
                "platforms": entries,
                "total_engagements": total_engagements,
            }
        )

    async def _public_api_report_engagement(self, request: web.Request) -> web.Response:
        """Record a public report click/engagement with cooldown."""
        domain_id = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        domain = await self.database.get_domain_by_id(domain_id)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found")

        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON payload"}, status=400)

        platform = (data.get("platform") or "").strip().lower()
        if not platform:
            return web.json_response({"error": "platform is required"}, status=400)

        available_platforms = {p.strip().lower() for p in self.get_available_platforms()}
        if platform not in available_platforms:
            return web.json_response({"error": "Unknown platform"}, status=400)

        session_hash = self._session_hash(request)
        count, cooldown = await self.database.record_report_engagement(
            domain_id=domain_id,
            platform=platform,
            session_hash=session_hash,
            cooldown_hours=24,
        )

        return web.json_response(
            {
                "status": "cooldown" if cooldown else "recorded",
                "platform": platform,
                "new_count": count,
                "message": "You've already reported recently." if cooldown else "Thank you for reporting!",
            }
        )

    async def _public_api_rescan_request(self, request: web.Request) -> web.Response:
        """Record a public rescan request for takedown-confirmed domains."""
        domain_id = _coerce_int(request.match_info.get("domain_id"), default=0, min_value=1)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")

        domain = await self.database.get_domain_by_id(domain_id)
        if not domain:
            raise web.HTTPNotFound(text="Domain not found")

        takedown_status = str(domain.get("takedown_status") or "").strip().lower()
        if takedown_status != "confirmed_down":
            return web.json_response(
                {"error": "Rescan requests are only available once a takedown is confirmed."},
                status=409,
            )

        if not self.rescan_callback:
            return web.json_response({"error": "Rescan not configured"}, status=503)

        session_hash = self._session_hash(request)
        threshold = max(1, int(getattr(self.config, "public_rescan_threshold", 3) or 3))
        window_hours = max(1, int(getattr(self.config, "public_rescan_window_hours", 24) or 24))
        cooldown_hours = max(1, int(getattr(self.config, "public_rescan_cooldown_hours", 24) or 24))

        count, cooldown = await self.database.record_rescan_request(
            domain_id=domain_id,
            session_hash=session_hash,
            cooldown_hours=cooldown_hours,
            window_hours=window_hours,
        )

        if cooldown:
            return web.json_response(
                {
                    "status": "cooldown",
                    "count": count,
                    "threshold": threshold,
                    "window_hours": window_hours,
                    "cooldown_hours": cooldown_hours,
                    "message": "You've already requested a rescan recently.",
                }
            )

        if count >= threshold:
            self.rescan_callback(str(domain.get("domain") or ""))
            await self.database.clear_rescan_requests(domain_id)
            return web.json_response(
                {
                    "status": "rescan_queued",
                    "count": count,
                    "threshold": threshold,
                    "window_hours": window_hours,
                    "cooldown_hours": cooldown_hours,
                    "message": "Rescan queued. We'll recheck the site shortly.",
                }
            )

        remaining = max(threshold - count, 0)
        return web.json_response(
            {
                "status": "queued",
                "count": count,
                "threshold": threshold,
                "remaining": remaining,
                "window_hours": window_hours,
                "cooldown_hours": cooldown_hours,
                "message": f"Thanks. We will rescan after {remaining} more request(s).",
            }
        )

    async def _public_api_analytics(self, request: web.Request) -> web.Response:
        """Return public-safe analytics (engagement + takedown stats)."""
        engagement = await self.database.get_engagement_summary()
        takedown = await self.database.get_takedown_metrics()
        return web.json_response({"engagement": engagement, "takedown": takedown})
