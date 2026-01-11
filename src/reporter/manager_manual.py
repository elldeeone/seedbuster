"""Manual report helper methods."""

from __future__ import annotations

import logging
from typing import Optional

from .base import ReportStatus

logger = logging.getLogger(__name__)


class ReportManagerManualMixin:
    """Manual report helpers."""

    async def get_manual_report_options(
        self,
        domain_id: int,
        domain: str,
        platforms: Optional[list[str]] = None,
        *,
        public: bool = False,
    ) -> dict[str, dict]:
        """Build manual submission instructions for the given domain/platforms."""
        if platforms is None:
            platforms = self.get_available_platforms()
        if not platforms:
            return {}

        evidence = await self.build_evidence(domain_id, domain)
        if not evidence:
            return {}

        hosting_hints: set[str] = set()
        service_hints: set[str] = set()
        registrar_name: Optional[str] = None
        registrar_abuse_email: Optional[str] = None
        registrar_matches: set[str] = set()

        hosting_specific = {
            "digitalocean",
            "aws",
            "gcp",
            "azure",
            "vercel",
            "netlify",
            "njalla",
            "render",
            "fly_io",
            "railway",
            "cloudflare",
            "hosting_provider",
            "edge_provider",
            "dns_provider",
        }
        registrar_specific = {
            "registrar",
            "godaddy",
            "namecheap",
            "porkbun",
            "google_domains",
            "tucows",
        }
        service_specific = {"telegram", "discord"}

        if any(p in hosting_specific for p in platforms):
            hosting_hints = await self._collect_hosting_hints_async(evidence)
        if any(p in registrar_specific for p in platforms):
            registrar_name, registrar_abuse_email = await self._detect_registrar_hint(evidence)
            registrar_matches = self._registrar_platforms_for(registrar_name)
        if any(p in service_specific for p in platforms):
            service_hints = self._collect_service_hints(evidence)

        results: dict[str, dict] = {}
        for platform in platforms:
            reporter = self.reporters.get(platform)
            if not reporter or not reporter.is_configured():
                continue
            if getattr(reporter, "public_exclude", False):
                logger.debug("Skipping %s for manual instructions (public_exclude)", platform)
                continue
            applicable, reason = self._platform_applicable(
                platform=platform,
                reporter=reporter,
                evidence=evidence,
                hosting_hints=hosting_hints,
                registrar_name=registrar_name,
                registrar_matches=registrar_matches,
                service_hints=service_hints,
                registrar_abuse_email=registrar_abuse_email,
            )
            if not applicable:
                logger.debug("Skipping %s for %s: %s", platform, domain, reason)
                continue
            try:
                manual = None
                if platform == "registrar" and hasattr(reporter, "generate_manual_submission_with_hints"):
                    manual = reporter.generate_manual_submission_with_hints(
                        evidence,
                        registrar_name=registrar_name,
                        registrar_abuse_email=registrar_abuse_email,
                    )
                else:
                    manual = reporter.generate_manual_submission(evidence)
                data = manual.to_dict() if hasattr(manual, "to_dict") else dict(manual)

                if isinstance(data, dict):
                    notes = data.get("notes")
                    if not isinstance(notes, list):
                        notes = []
                    notes = list(notes)
                    data["notes"] = notes
                    if platform in hosting_hints:
                        context = f"Hosting detected: {platform.replace('_', ' ').title()}"
                        if context not in notes:
                            notes.insert(0, context)
                    if platform in registrar_specific or platform == "registrar":
                        if registrar_name:
                            context = f"Registrar detected: {registrar_name.title()}"
                            if context not in notes:
                                notes.insert(0, context)
                        elif registrar_abuse_email:
                            context = f"Registrar abuse contact found: {registrar_abuse_email}"
                            if context not in notes:
                                notes.insert(0, context)
                    if public:
                        data = self._scrub_public_identity(data)
                        notes = data.get("notes")
                        if not isinstance(notes, list):
                            notes = []
                        notes = list(notes)
                        data["notes"] = notes
                        if "Use your own contact details" not in notes:
                            notes.append("Use your own contact details.")
                    form_url = str(data.get("form_url") or "").strip() if isinstance(data, dict) else ""
                    if not form_url:
                        missing = "Destination missing; research needed."
                        if isinstance(notes, list) and missing not in notes:
                            notes.insert(0, missing)

                results[platform] = data
            except Exception as exc:
                results[platform] = {"error": str(exc)}
        return self._dedupe_generic_provider_reports(results)

    async def ensure_pending_reports(self, domain_id: int, platforms: Optional[list[str]] = None) -> None:
        """Ensure there is a pending report row per platform."""
        if platforms is None:
            platforms = self.get_available_platforms()
        if not platforms:
            return

        existing = await self.database.get_reports_for_domain(domain_id)
        existing_platforms = {str(r.get("platform") or "").strip().lower() for r in existing}

        for platform in platforms:
            key = (platform or "").strip().lower()
            if not key or key in existing_platforms:
                continue
            await self.database.add_report(
                domain_id=domain_id,
                platform=key,
                status=ReportStatus.PENDING.value,
            )
