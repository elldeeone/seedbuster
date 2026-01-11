"""Report evidence builder."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from .base import ReportEvidence
from ..utils.reporting import select_report_url

logger = logging.getLogger(__name__)


class ReportManagerEvidenceMixin:
    """Evidence building helpers."""

    async def build_evidence(
        self,
        domain_id: int,
        domain: str,
    ) -> Optional[ReportEvidence]:
        """Build evidence package from stored analysis data."""
        domain_data = await self.database.get_domain_by_id(domain_id)
        if not domain_data:
            logger.warning("Domain not found: %s", domain_id)
            return None

        evidence_dir = self.evidence_store.get_evidence_path(domain)

        analysis_json = {}
        analysis_path = self.evidence_store.get_analysis_path(domain)
        if analysis_path and analysis_path.exists():
            analysis_json = self.evidence_store.load_analysis(domain) or {}

        detection_reasons = analysis_json.get("reasons") or []
        if not detection_reasons:
            verdict_reasons = domain_data.get("verdict_reasons") or ""
            detection_reasons = [r.strip() for r in verdict_reasons.splitlines() if r.strip()]

        target = (domain or "").strip()
        hostname = self._extract_hostname(target) or target.lower()

        final_url = (analysis_json.get("final_url") or "").strip()
        initial_url = (
            analysis_json.get("initial_url") or analysis_json.get("source_url") or ""
        ).strip()
        report_url = select_report_url(
            target,
            final_url=final_url,
            initial_url=initial_url,
        )

        suspicious_endpoints = analysis_json.get("suspicious_endpoints", []) or []

        backend_domains = analysis_json.get("backend_domains")
        if not backend_domains:
            backend_domains = self._extract_hostnames_from_endpoints(suspicious_endpoints)

        api_keys_found = analysis_json.get("api_keys_found")
        if not api_keys_found:
            api_keys_found = self._extract_api_key_indicators(detection_reasons)

        hosting_provider = analysis_json.get("hosting_provider")
        if not hosting_provider:
            hosting_provider = (analysis_json.get("infrastructure") or {}).get("hosting_provider")

        scam_type = (analysis_json.get("scam_type") or domain_data.get("scam_type") or "").strip() or None
        scammer_wallets = analysis_json.get("scammer_wallets") or []
        if isinstance(scammer_wallets, str):
            scammer_wallets = [scammer_wallets]
        if not isinstance(scammer_wallets, list):
            scammer_wallets = []

        screenshot_path = None
        try:
            shots = self.evidence_store.get_all_screenshot_paths(domain)
            screenshot_path = shots[0] if shots else None
        except Exception:
            screenshot_path = None
        if not screenshot_path:
            screenshot_path = self.evidence_store.get_screenshot_path(domain)

        evidence = ReportEvidence(
            domain=hostname,
            url=report_url,
            detected_at=datetime.fromisoformat(
                domain_data.get("first_seen", datetime.now().isoformat())
            ),
            confidence_score=domain_data.get("analysis_score", 0),
            domain_id=domain_id,
            detection_reasons=detection_reasons,
            suspicious_endpoints=suspicious_endpoints,
            screenshot_path=screenshot_path,
            html_path=evidence_dir / "page.html" if evidence_dir else None,
            analysis_path=analysis_path,
            analysis_json=analysis_json,
            backend_domains=backend_domains,
            api_keys_found=api_keys_found,
            hosting_provider=hosting_provider,
            scam_type=scam_type,
            scammer_wallets=[str(w).strip() for w in scammer_wallets if str(w).strip()],
        )

        return evidence
