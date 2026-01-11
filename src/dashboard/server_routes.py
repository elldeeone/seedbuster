"""Route registration for dashboard server."""

from __future__ import annotations

class DashboardServerRoutesMixin:
    """Route registration helper."""

    def _register_routes(self) -> None:
        # Health check
        self._app.router.add_get("/healthz", self._healthz)

        # Public API routes (read-only, reuse admin handlers)
        self._app.router.add_get("/api/stats", self._admin_api_stats)
        self._app.router.add_get("/api/domains", self._admin_api_domains)
        self._app.router.add_get("/api/campaigns", self._admin_api_campaigns)
        self._app.router.add_get("/api/campaigns/{campaign_id}", self._admin_api_campaign)
        self._app.router.add_get("/api/domains/{domain_id}", self._admin_api_domain)
        self._app.router.add_get("/api/platforms", self._admin_api_platforms)
        self._app.router.add_post("/api/public/submit", self._public_api_submit)
        self._app.router.add_get("/api/domains/{domain_id}/report-options", self._public_api_report_options)
        self._app.router.add_post("/api/domains/{domain_id}/report-engagement", self._public_api_report_engagement)
        self._app.router.add_post("/api/domains/{domain_id}/rescan-request", self._public_api_rescan_request)
        self._app.router.add_get("/api/analytics", self._public_api_analytics)
        self._app.router.add_get("/api/scams.json", self._public_api_scams_json)
        self._app.router.add_route("OPTIONS", "/api/scams.json", self._public_api_scams_options)

        # Evidence directory is public by design for transparency.
        self._app.router.add_static("/evidence", str(self.evidence_dir), show_index=False)
        # Public download routes for reports/evidence packages
        self._app.router.add_get("/domains/{domain_id}/pdf", self._admin_domain_pdf)
        self._app.router.add_get("/domains/{domain_id}/package", self._admin_domain_package)
        self._app.router.add_get("/campaigns/{campaign_id}/pdf", self._admin_campaign_pdf)
        self._app.router.add_get("/campaigns/{campaign_id}/package", self._admin_campaign_package)

        # Admin API routes
        self._app.router.add_get("/admin/api/stats", self._admin_api_stats)
        self._app.router.add_get("/admin/api/domains", self._admin_api_domains)
        self._app.router.add_get("/admin/api/domains/{domain_id}", self._admin_api_domain)
        self._app.router.add_get("/admin/api/takedown-checks", self._admin_api_takedown_checks)
        self._app.router.add_post("/admin/api/submit", self._admin_api_submit)
        self._app.router.add_post("/admin/api/domains/{domain_id}/rescan", self._admin_api_rescan)
        self._app.router.add_post("/admin/api/domains/bulk-rescan", self._admin_api_bulk_rescan)
        self._app.router.add_get("/admin/api/domains/bulk-rescan/{bulk_id}", self._admin_api_bulk_rescan_status)
        self._app.router.add_post("/admin/api/report", self._admin_api_report)
        self._app.router.add_post(
            "/admin/api/domains/{domain_id}/false_positive",
            self._admin_api_false_positive,
        )
        self._app.router.add_patch(
            "/admin/api/domains/{domain_id}/status",
            self._admin_api_update_domain_status,
        )
        self._app.router.add_patch(
            "/admin/api/domains/{domain_id}/takedown",
            self._admin_api_update_domain_takedown_status,
        )
        self._app.router.add_patch(
            "/admin/api/domains/{domain_id}/takedown-override",
            self._admin_api_update_domain_takedown_override,
        )
        self._app.router.add_post("/admin/api/domains/{domain_id}/baseline", self._admin_api_update_baseline)
        self._app.router.add_get("/admin/api/domains/{domain_id}/evidence", self._admin_api_evidence)
        self._app.router.add_get("/admin/api/domains/{domain_id}/report-options", self._admin_api_report_options)
        self._app.router.add_post("/admin/api/cleanup_evidence", self._admin_api_cleanup_evidence)
        self._app.router.add_get("/admin/api/campaigns", self._admin_api_campaigns)
        self._app.router.add_get("/admin/api/campaigns/{campaign_id}", self._admin_api_campaign)
        self._app.router.add_patch("/admin/api/domains/{domain_id}/notes", self._admin_api_update_notes)
        self._app.router.add_patch(
            "/admin/api/campaigns/{campaign_id}/name",
            self._admin_api_update_campaign_name,
        )
        self._app.router.add_get("/admin/api/platforms", self._admin_api_platforms)
        self._app.router.add_get("/admin/api/analytics", self._admin_api_analytics)
        self._app.router.add_get("/admin/api/detection-metrics", self._admin_api_detection_metrics)
        self._app.router.add_get("/admin/api/allowlist", self._admin_api_allowlist)
        self._app.router.add_post("/admin/api/allowlist", self._admin_api_allowlist_add)
        self._app.router.add_post("/admin/api/allowlist/remove", self._admin_api_allowlist_remove)
        self._app.router.add_get("/admin/api/submissions", self._admin_api_submissions)
        self._app.router.add_get("/admin/api/submissions/{submission_id}", self._admin_api_submission)
        self._app.router.add_post(
            "/admin/api/submissions/{submission_id}/approve",
            self._admin_api_approve_submission,
        )
        self._app.router.add_post(
            "/admin/api/submissions/{submission_id}/reject",
            self._admin_api_reject_submission,
        )

        self._app.router.add_get("/admin/domains/{domain_id}/pdf", self._admin_domain_pdf)
        self._app.router.add_get("/admin/domains/{domain_id}/package", self._admin_domain_package)
        self._app.router.add_post("/admin/domains/{domain_id}/preview", self._admin_domain_preview)
        # Campaign routes
        self._app.router.add_get("/admin/campaigns/{campaign_id}/pdf", self._admin_campaign_pdf)
        self._app.router.add_get("/admin/campaigns/{campaign_id}/package", self._admin_campaign_package)
        self._app.router.add_post("/admin/campaigns/{campaign_id}/preview", self._admin_campaign_preview)
        self._app.router.add_post("/admin/campaigns/{campaign_id}/submit", self._admin_campaign_submit)

        # UI routes: prefer SPA when built; fall back to server-rendered HTML otherwise
        if self._frontend_available:
            assets_dir = self.frontend_dir / "assets"
            if assets_dir.exists():
                self._app.router.add_static("/admin/assets", str(assets_dir), show_index=False)
                self._app.router.add_static("/assets", str(assets_dir), show_index=False)
            self._app.router.add_get("/admin", self._serve_frontend)
            self._app.router.add_get("/admin/", self._serve_frontend)
            self._app.router.add_get("/admin/{tail:.*}", self._serve_frontend)
            self._app.router.add_get("/", self._serve_frontend)
            self._app.router.add_get("/campaigns", self._serve_frontend)
            self._app.router.add_get("/campaigns/{tail:.*}", self._serve_frontend)
        else:
            self._app.router.add_get("/admin", self._admin_index)
            self._app.router.add_get("/admin/campaigns", self._admin_campaigns)
            self._app.router.add_get("/admin/campaigns/{campaign_id}", self._admin_campaign_detail)
            self._app.router.add_get("/admin/domains/{domain_id}", self._admin_domain)
            self._app.router.add_post("/admin/domains/{domain_id}/update", self._admin_update_domain)
            self._app.router.add_post("/admin/domains/{domain_id}/report", self._admin_report_domain)
            self._app.router.add_post("/admin/domains/{domain_id}/manual_done", self._admin_manual_done)
            self._app.router.add_post("/admin/domains/{domain_id}/rescan", self._admin_rescan)
            self._app.router.add_post("/admin/domains/{domain_id}/false_positive", self._admin_false_positive)
            self._app.router.add_post("/admin/submit", self._admin_submit)

            self._app.router.add_get("/", self._public_index)
            self._app.router.add_get("/domains/{domain_id}", self._public_domain)
            self._app.router.add_get("/campaigns", self._public_campaigns)
            self._app.router.add_get("/campaigns/{campaign_id}", self._public_campaign_detail)
