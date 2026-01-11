"""Admin domain API handlers."""

from __future__ import annotations

import asyncio
import ipaddress
import socket

from aiohttp import web

from ..storage.database import DomainStatus
from ..utils.domains import canonicalize_domain
from .server_helpers import _coerce_int, _domain_dir_name


class DashboardServerAdminApiDomainsMixin:
    """Admin domain API."""

    async def _admin_api_domains(self, request: web.Request) -> web.Response:
        status = (request.query.get("status") or "").strip().lower()
        verdict = (request.query.get("verdict") or "").strip().lower()
        q = (request.query.get("q") or "").strip().lower()
        exclude_statuses_raw = (request.query.get("exclude_statuses") or "").strip().lower()
        exclude_takedowns = (request.query.get("exclude_takedowns") or "").strip().lower() in {"1", "true", "yes"}
        limit = _coerce_int(request.query.get("limit"), default=50, min_value=1, max_value=500)
        page = _coerce_int(request.query.get("page"), default=1, min_value=1, max_value=10_000)
        offset = (page - 1) * limit

        exclude_statuses = None
        if exclude_statuses_raw and not status:
            exclude_statuses = [s.strip() for s in exclude_statuses_raw.split(",") if s.strip()]

        domains = await self.database.list_domains(
            limit=limit,
            offset=offset,
            status=status or None,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
            exclude_takedowns=exclude_takedowns,
        )
        total = await self.database.count_domains(
            status=status or None,
            verdict=verdict or None,
            query=q or None,
            exclude_statuses=exclude_statuses,
            exclude_takedowns=exclude_takedowns,
        )
        return web.json_response(
            {
                "domains": domains,
                "page": page,
                "limit": limit,
                "count": len(domains),
                "total": total,
            }
        )

    async def _admin_api_domain(self, request: web.Request) -> web.Response:
        domain_id = int(request.match_info.get("domain_id") or 0)
        if not domain_id:
            raise web.HTTPBadRequest(text="domain_id required")
        snapshot_param = (request.query.get("snapshot") or "").strip()
        row = await self.database.get_domain_by_id(domain_id)
        if not row:
            raise web.HTTPNotFound(text="Domain not found")

        is_allowlisted = (
            str(row.get("status") or "").strip().lower() == DomainStatus.ALLOWLISTED.value
            or self._is_allowlisted_domain(row["domain"])
        )
        reports = [] if is_allowlisted else await self.database.get_reports_for_domain(domain_id)
        takedown_checks = (
            [] if is_allowlisted else await self.database.get_recent_takedown_checks(domain_id)
        )
        evidence = {}
        infrastructure = {}
        redirect_info: dict | None = None
        instruction_files: list[str] = []
        snapshot: dict | None = None
        snapshots: list[dict] = []
        latest_id: str | None = None
        campaign = self._get_campaign_for_domain(row["domain"])
        filtered_campaign = None
        if campaign:
            filtered = await self._filter_campaigns([campaign])
            filtered_campaign = filtered[0] if filtered else None
        related_domains = await self._enrich_related_domains_with_ids(
            self._get_related_domains(row["domain"], filtered_campaign)
        )
        if not is_allowlisted:
            try:
                domain_dir = self.evidence_dir / _domain_dir_name(row["domain"])
                snapshots, latest_id = self._list_snapshots(domain_dir)
                snapshot_dir, resolved_snapshot_id, is_latest = self._resolve_snapshot_dir(
                    domain_dir, snapshot_param, latest_id
                )
                if snapshot_param and not snapshot_dir:
                    return web.json_response({"error": "Snapshot not found"}, status=404)

                evidence_cache_buster = resolved_snapshot_id or latest_id
                cache_suffix = f"?v={evidence_cache_buster}" if evidence_cache_buster else ""
                evidence_base = f"/evidence/{domain_dir.name}"
                if snapshot_dir and not is_latest and resolved_snapshot_id:
                    evidence_base = f"/evidence/{domain_dir.name}/runs/{resolved_snapshot_id}"

                if snapshot_dir:
                    evidence["html"] = (
                        f"{evidence_base}/page.html{cache_suffix}"
                        if (snapshot_dir / "page.html").exists()
                        else None
                    )
                    evidence["analysis"] = (
                        f"{evidence_base}/analysis.json{cache_suffix}"
                        if (snapshot_dir / "analysis.json").exists()
                        else None
                    )
                    evidence["screenshots"] = [
                        f"{evidence_base}/{p.name}{cache_suffix}"
                        for p in self._get_screenshots(row, snapshot_dir)
                    ]

                if is_latest and domain_dir.exists():
                    instruction_files = [
                        f"/evidence/{domain_dir.name}/{p.name}{cache_suffix}"
                        for p in self._get_instruction_files(domain_dir)
                    ]

                analysis_path = snapshot_dir / "analysis.json" if snapshot_dir else None
                if analysis_path and analysis_path.exists():
                    import json

                    try:
                        data = json.loads(analysis_path.read_text())
                        infra = data.get("infrastructure") or {}
                        nameservers = infra.get("nameservers") or []
                        if isinstance(nameservers, str):
                            nameservers = [nameservers] if nameservers else []
                        ip_addresses = infra.get("ip_addresses") or data.get("resolved_ips") or []
                        if isinstance(ip_addresses, str):
                            ip_addresses = [ip_addresses] if ip_addresses else []
                        origin_provider = infra.get("hosting_provider") or data.get("hosting_provider")
                        edge_provider = infra.get("edge_provider") or data.get("edge_provider")
                        infrastructure = {
                            "hosting_provider": origin_provider,
                            "edge_provider": edge_provider,
                            "registrar": infra.get("registrar") or data.get("registrar"),
                            "nameservers": nameservers,
                            "ip_addresses": ip_addresses,
                            "tls_age_days": infra.get("tls_age_days"),
                            "domain_age_days": infra.get("domain_age_days"),
                        }
                        snapshot = {
                            "id": resolved_snapshot_id or latest_id,
                            "timestamp": data.get("saved_at"),
                            "score": data.get("score"),
                            "verdict": data.get("verdict"),
                            "reasons": data.get("reasons"),
                            "scan_reason": data.get("scan_reason"),
                            "is_latest": is_latest,
                            "source_url": data.get("source_url"),
                            "final_url": data.get("final_url"),
                        }
                        final_url = data.get("final_url")
                        final_domain = data.get("final_domain") or canonicalize_domain(final_url or "")
                        redirect_chain = data.get("redirect_chain") or []
                        if isinstance(redirect_chain, dict):
                            redirect_chain = [redirect_chain]
                        if not isinstance(redirect_chain, list):
                            redirect_chain = []
                        redirect_info = {
                            "initial_url": data.get("initial_url") or data.get("source_url") or None,
                            "early_url": data.get("early_url") or None,
                            "final_url": final_url or None,
                            "final_domain": final_domain or None,
                            "redirect_detected": bool(data.get("redirect_detected")) or bool(redirect_chain),
                            "redirect_hops": data.get("redirect_hops") if data.get("redirect_hops") is not None else len(redirect_chain),
                            "redirect_chain": redirect_chain,
                            "redirect_only": data.get("redirect_only") if data.get("redirect_only") is not None else None,
                            "redirect_service": data.get("redirect_service") or None,
                            "redirect_service_header": data.get("redirect_service_header") or None,
                        }
                    except Exception:
                        infrastructure = {}
                        snapshot = None
                        redirect_info = None
                else:
                    infrastructure = {}
            except Exception:
                evidence = {}
                redirect_info = None

        domain_name = str(row.get("domain") or "").strip()
        if domain_name:
            try:
                if infrastructure.get("ip_addresses") in (None, [], ()):
                    cached_ips = self._cache_get(self._dns_cache, domain_name)
                    if cached_ips is None:
                        loop = asyncio.get_event_loop()
                        addrs = await loop.run_in_executor(
                            None,
                            lambda: socket.getaddrinfo(domain_name, None, socket.AF_UNSPEC, socket.SOCK_STREAM),
                        )
                        ips = sorted({sockaddr[0] for *_rest, sockaddr in addrs})
                        global_ips = []
                        for ip in ips:
                            try:
                                if ipaddress.ip_address(ip).is_global:
                                    global_ips.append(ip)
                            except ValueError:
                                continue
                        cached_ips = global_ips or ips
                        self._cache_set(self._dns_cache, domain_name, cached_ips)
                    infrastructure["ip_addresses"] = cached_ips
            except Exception:
                pass

            try:
                if not infrastructure.get("nameservers"):
                    cached_ns = self._cache_get(self._ns_cache, domain_name)
                    if cached_ns is None:
                        session = await self._get_http_session()
                        params = {"name": domain_name, "type": "NS"}
                        async with session.get("https://dns.google/resolve", params=params) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                answers = data.get("Answer") or []
                                ns = []
                                for ans in answers:
                                    raw = str(ans.get("data", "")).strip()
                                    if raw:
                                        ns.append(raw.rstrip("."))
                                cached_ns = ns
                            else:
                                cached_ns = []
                        self._cache_set(self._ns_cache, domain_name, cached_ns)
                    if cached_ns:
                        infrastructure["nameservers"] = cached_ns
            except Exception:
                pass

        if redirect_info and isinstance(redirect_info, dict):
            final_domain = redirect_info.get("final_domain")
            current_canonical = canonicalize_domain(domain_name)
            final_canonical = canonicalize_domain(final_domain or "")
            if final_canonical and current_canonical and final_canonical != current_canonical:
                try:
                    target_row = await self.database.get_domain(final_canonical)
                except Exception:
                    target_row = None
                if target_row:
                    redirect_info["target"] = {
                        "id": target_row.get("id"),
                        "domain": target_row.get("domain"),
                        "status": target_row.get("status"),
                        "verdict": target_row.get("verdict"),
                    }
                else:
                    redirect_info["target"] = {"domain": final_canonical}

        rescan_request_info = None
        try:
            threshold = max(1, int(getattr(self.config, "public_rescan_threshold", 3) or 3))
            window_hours = max(1, int(getattr(self.config, "public_rescan_window_hours", 24) or 24))
            cooldown_hours = max(1, int(getattr(self.config, "public_rescan_cooldown_hours", 24) or 24))
            count = await self.database.get_rescan_request_count(domain_id, window_hours=window_hours)
            rescan_request_info = {
                "count": count,
                "threshold": threshold,
                "window_hours": window_hours,
                "cooldown_hours": cooldown_hours,
            }
        except Exception:
            rescan_request_info = None

        selected_snapshot_id = None
        if snapshots:
            selected_snapshot_id = None
            if snapshot and snapshot.get("id"):
                selected_snapshot_id = snapshot.get("id")
            elif snapshot_param:
                selected_snapshot_id = snapshot_param
            elif "latest_id" in locals():
                selected_snapshot_id = latest_id

        return web.json_response(
            {
                "domain": row,
                "reports": self._filter_reports_for_snapshot(reports, snapshots, selected_snapshot_id),
                "evidence": evidence,
                "infrastructure": infrastructure,
                "redirect": redirect_info,
                "campaign": filtered_campaign,
                "related_domains": related_domains,
                "instruction_files": instruction_files,
                "rescan_request": rescan_request_info,
                "takedown_checks": takedown_checks,
                "snapshots": snapshots,
                "snapshot": snapshot,
            }
        )
