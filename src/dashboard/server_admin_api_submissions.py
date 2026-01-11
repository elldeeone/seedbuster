"""Admin submission API handlers."""

from __future__ import annotations

from aiohttp import web

from ..utils.domains import canonicalize_domain, normalize_source_url
from .server_helpers import _coerce_int, _extract_hostname, _format_public_submission_notes


class DashboardServerAdminApiSubmissionsMixin:
    """Admin submission API."""

    async def _admin_api_submissions(self, request: web.Request) -> web.Response:
        status = (request.query.get("status") or "pending_review").strip() or None
        limit = _coerce_int(request.query.get("limit"), default=100, min_value=1, max_value=500)
        page = _coerce_int(request.query.get("page"), default=1, min_value=1, max_value=10_000)
        offset = (page - 1) * limit

        submissions = await self.database.get_public_submissions(status=status, limit=limit, offset=offset)
        total = await self.database.count_public_submissions(status=status)
        total_pending = await self.database.count_public_submissions(status="pending_review")

        return web.json_response(
            {
                "submissions": submissions,
                "page": page,
                "limit": limit,
                "count": len(submissions),
                "total": total,
                "total_pending": total_pending,
            }
        )

    async def _admin_api_submission(self, request: web.Request) -> web.Response:
        submission_id = _coerce_int(request.match_info.get("submission_id"), default=0, min_value=1)
        if not submission_id:
            raise web.HTTPBadRequest(text="submission_id required")
        submission = await self.database.get_public_submission(submission_id)
        if not submission:
            raise web.HTTPNotFound(text="Submission not found")
        return web.json_response({"submission": submission})

    async def _admin_api_submit(self, request: web.Request) -> web.Response:
        self._require_csrf_header(request)
        data = await self._read_json(request)
        target = (data.get("target") or data.get("domain") or "").strip()
        domain = canonicalize_domain(target) or _extract_hostname(target)
        if not domain:
            return web.json_response({"error": "Invalid domain/URL"}, status=400)
        source_url = None
        if "/" in target or target.startswith(("http://", "https://")):
            source_url = self._normalize_source_url(target, canonical=domain)

        existing = await self.database.get_domain(domain)
        if existing:
            if source_url and self.submit_callback:
                self._invoke_submit_callback(domain, source_url)
                return web.json_response({"status": "rescan_queued", "domain": domain})
            if self.rescan_callback:
                already = await self.database.has_pending_dashboard_action("rescan_domain", domain)
                if already:
                    return web.json_response({"status": "already_queued", "domain": domain})
                self.rescan_callback(domain)
                return web.json_response({"status": "rescan_queued", "domain": domain})
            return web.json_response({"status": "already_queued", "domain": domain})

        if not self.submit_callback:
            raise web.HTTPServiceUnavailable(text="Submit not configured")

        self._invoke_submit_callback(domain, source_url)
        return web.json_response({"status": "submitted", "domain": domain})

    async def _admin_api_approve_submission(self, request: web.Request) -> web.Response:
        self._require_csrf_header(request)
        submission_id = _coerce_int(request.match_info.get("submission_id"), default=0, min_value=1)
        if not submission_id:
            raise web.HTTPBadRequest(text="submission_id required")

        submission = await self.database.get_public_submission(submission_id)
        if not submission:
            raise web.HTTPNotFound(text="Submission not found")

        if str(submission.get("status") or "").strip().lower() != "pending_review":
            return web.json_response({"error": "Submission already reviewed"}, status=400)

        data = await self._read_json(request, allow_empty=True)
        reviewer_notes = (data.get("notes") or "").strip()
        if reviewer_notes and len(reviewer_notes) > 1000:
            reviewer_notes = reviewer_notes[:1000]

        domain_value = (submission.get("canonical_domain") or submission.get("domain") or "").strip()
        canonical = canonicalize_domain(domain_value)
        if not canonical:
            return web.json_response({"error": "Invalid domain"}, status=400)

        existing = await self.database.get_domain_by_canonical(canonical)
        if existing:
            await self.database.update_public_submission_status(
                submission_id=submission_id,
                status="duplicate",
                reviewer_notes=reviewer_notes or "Already tracked",
                promoted_domain_id=int(existing.get("id") or 0),
            )
            return web.json_response(
                {
                    "status": "duplicate",
                    "domain": existing.get("domain"),
                    "domain_id": existing.get("id"),
                }
            )

        source_url = None
        submitted_url = None
        public_notes = None
        if isinstance(submission, dict):
            source_url = normalize_source_url(submission.get("source_url"))
            submitted_url = normalize_source_url(
                submission.get("submitted_url"),
                canonical=canonical,
            )
            public_notes = _format_public_submission_notes(
                submitted_url,
                source_url,
                submission.get("reporter_notes"),
            )
            if public_notes:
                public_notes = f"Public submission:\n{public_notes}"

        domain_id = await self.database.add_domain(
            domain=canonical,
            source="public_submission",
            domain_score=0,
            source_url=None,
        )

        if not domain_id:
            existing = await self.database.get_domain_by_canonical(canonical)
            domain_id = int(existing.get("id") or 0) if existing else 0

        if not domain_id:
            return web.json_response({"error": "Failed to create domain"}, status=500)

        if not self.submit_callback:
            raise web.HTTPServiceUnavailable(text="Submit callback not configured")
        self._invoke_submit_callback(canonical, None)
        if submitted_url and not self._is_root_source_url(submitted_url):
            self._invoke_submit_callback(canonical, submitted_url)
        if public_notes:
            domain_row = await self.database.get_domain_by_id(domain_id)
            existing_notes = (domain_row.get("operator_notes") or "").strip() if domain_row else ""
            combined_notes = f"{existing_notes}\n{public_notes}" if existing_notes else public_notes
            await self.database.update_domain_admin_fields(
                domain_id,
                operator_notes=combined_notes,
            )
        await self.database.update_public_submission_status(
            submission_id=submission_id,
            status="approved",
            reviewer_notes=reviewer_notes or None,
            promoted_domain_id=domain_id,
        )

        return web.json_response({"status": "approved", "domain": canonical, "domain_id": domain_id})

    async def _admin_api_reject_submission(self, request: web.Request) -> web.Response:
        self._require_csrf_header(request)
        submission_id = _coerce_int(request.match_info.get("submission_id"), default=0, min_value=1)
        if not submission_id:
            raise web.HTTPBadRequest(text="submission_id required")

        submission = await self.database.get_public_submission(submission_id)
        if not submission:
            raise web.HTTPNotFound(text="Submission not found")

        if str(submission.get("status") or "").strip().lower() != "pending_review":
            return web.json_response({"error": "Submission already reviewed"}, status=400)

        data = await self._read_json(request, allow_empty=True)

        reason = (data.get("reason") or "rejected").strip().lower()
        notes = (data.get("notes") or "").strip()
        if notes and len(notes) > 1000:
            notes = notes[:1000]

        await self.database.update_public_submission_status(
            submission_id=submission_id,
            status=reason or "rejected",
            reviewer_notes=notes or None,
            promoted_domain_id=None,
        )
        return web.json_response({"status": "rejected", "reason": reason})

    async def _admin_api_bulk_rescan(self, request: web.Request) -> web.Response:
        """Queue rescan actions for multiple domains (admin-only)."""
        import uuid

        self._require_csrf_header(request)
        if not self.rescan_callback:
            raise web.HTTPServiceUnavailable(text="Rescan not configured")
        data = await self._read_json(request)
        domain_ids = data.get("domain_ids") or []
        if not isinstance(domain_ids, list) or not domain_ids:
            return web.json_response({"error": "domain_ids list required"}, status=400)

        ids: list[int] = []
        for value in domain_ids:
            try:
                ids.append(int(value))
            except Exception:
                continue
        ids = sorted(set(ids))
        if not ids:
            return web.json_response({"error": "No valid domain ids provided"}, status=400)

        rows = await self.database.get_domains_by_ids(ids)
        if not rows:
            return web.json_response({"error": "No domains found for provided ids"}, status=404)

        bulk_id = uuid.uuid4().hex
        queued = 0
        skipped = 0
        found_ids = set()
        for row in rows:
            domain_name = str(row.get("domain") or "").strip()
            if not domain_name:
                continue
            found_ids.add(int(row.get("id") or 0))
            action_id = await self.database.enqueue_dashboard_action(
                "rescan_domain",
                {"domain": domain_name},
                target=domain_name,
                bulk_id=bulk_id,
                dedupe=True,
            )
            if action_id:
                queued += 1
            else:
                skipped += 1

        missing = len({i for i in ids if i not in found_ids})
        status = await self.database.get_bulk_action_stats(bulk_id)
        return web.json_response(
            {
                "bulk_id": bulk_id,
                "requested": len(ids),
                "found": len(rows),
                "missing": missing,
                "queued": queued,
                "skipped": skipped,
                "status": status,
            }
        )

    async def _admin_api_bulk_rescan_status(self, request: web.Request) -> web.Response:
        """Return status counts for a bulk rescan batch."""
        bulk_id = (request.match_info.get("bulk_id") or "").strip()
        if not bulk_id:
            raise web.HTTPBadRequest(text="bulk_id required")
        status = await self.database.get_bulk_action_stats(bulk_id)
        if status.get("total", 0) <= 0:
            return web.json_response({"error": "Bulk batch not found"}, status=404)
        return web.json_response({"bulk_id": bulk_id, "status": status})
