"""Provider/service hint helpers for report manager."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Optional
from urllib.parse import urlparse

import httpx

from .base import BaseReporter, ReportEvidence
from ..utils.domains import canonicalize_domain

logger = logging.getLogger(__name__)


class ReportManagerHintsMixin:
    """Hosting/registrar/service hint helpers."""

    @staticmethod
    def _normalize_hint(value: Optional[str]) -> str:
        """Normalize provider/registrar strings for comparison."""
        return (value or "").strip().lower()

    def _extract_provider_from_reason(self, reason: object) -> str:
        text = str(reason or "").strip()
        if ":" not in text:
            return ""
        provider = text.split(":", 1)[1].strip()
        if not provider:
            return ""
        return self._canonical_provider(provider)

    def _dedupe_generic_provider_reports(self, results: dict[str, dict]) -> dict[str, dict]:
        generic = {"hosting_provider", "edge_provider", "dns_provider"}
        if not results:
            return results
        for platform in list(generic):
            data = results.get(platform)
            if not isinstance(data, dict):
                continue
            provider = self._extract_provider_from_reason(data.get("reason"))
            if provider and provider in results:
                results.pop(platform, None)
        return results

    def _canonical_provider(self, value: str) -> str:
        """Map provider aliases to platform keys used by reporters."""
        key = self._normalize_hint(value)
        if not key:
            return ""
        aliases = {
            "amazon": "aws",
            "amazon web services": "aws",
            "aws": "aws",
            "google cloud": "gcp",
            "google cloud platform": "gcp",
            "google": "gcp",
            "gcp": "gcp",
            "microsoft": "azure",
            "azure": "azure",
            "msft": "azure",
            "fly.io": "fly_io",
            "flyio": "fly_io",
            "fly": "fly_io",
            "fastly": "fastly",
            "akamai": "akamai",
            "sucuri": "sucuri",
            "wix": "wix",
            "squarespace": "squarespace",
            "shopify": "shopify",
            "vercel": "vercel",
            "netlify": "netlify",
            "railway": "railway",
            "render": "render",
        }
        return aliases.get(key, key)

    def _provider_host_candidates(self, evidence: ReportEvidence) -> list[str]:
        """Collect hostnames worth probing for provider signals (preserve priority)."""
        hosts: list[str] = []
        seen: set[str] = set()

        analysis = evidence.analysis_json or {}
        final_url = str(analysis.get("final_url") or "").strip()
        final_domain = canonicalize_domain(str(analysis.get("final_domain") or "")) or canonicalize_domain(final_url)
        current_domain = canonicalize_domain(evidence.domain) or canonicalize_domain(evidence.url)
        redirect_offsite = bool(final_domain and current_domain and final_domain != current_domain)

        def _add_host(raw: Optional[str]) -> None:
            if not raw:
                return
            parsed = urlparse(raw if "://" in raw else f"https://{raw}")
            host = (parsed.hostname or "").strip().lower()
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)

        _add_host(evidence.url)
        if not redirect_offsite:
            _add_host(final_url)

        if not redirect_offsite:
            for endpoint in evidence.suspicious_endpoints or []:
                _add_host(endpoint)
            for backend in evidence.backend_domains or []:
                _add_host(backend)

        return hosts

    def _detect_vercel_from_hosts(self, hosts: list[str]) -> set[str]:
        """Lightweight Vercel detection using DNS/IP ranges and headers."""
        hints: set[str] = set()
        if not hosts:
            return hints

        # Known Vercel edge ranges (documented for alias.vercel-dns.com)
        vercel_ip_prefixes = ("76.76.21.", "76.76.22.", "76.223.126.", "76.223.127.")
        header_keys = ("server", "x-vercel-id", "x-vercel-cache", "x-powered-by")

        for host in hosts[:5]:  # cap to avoid long probes
            if "vercel" in host:
                hints.add("vercel")
                continue

            try:
                infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
                ips = {info[4][0] for info in infos if info and info[4]}
            except Exception:
                ips = set()

            if any(ip.startswith(prefix) for prefix in vercel_ip_prefixes for ip in ips):
                hints.add("vercel")
                continue

            # As a fallback, probe headers for explicit Vercel markers
            try:
                resp = httpx.get(
                    f"https://{host}",
                    timeout=3.0,
                    follow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "SeedBuster/abuse-helper"},
                )
                header_values = " ".join(resp.headers.get(k, "") for k in header_keys).lower()
                if "vercel" in header_values:
                    hints.add("vercel")
            except Exception:
                continue

        return hints

    def _collect_hosting_hints(self, evidence: ReportEvidence) -> set[str]:
        """Collect hosting/provider hints from analysis outputs and endpoints."""
        hints: set[str] = set()

        candidates = [
            evidence.hosting_provider,
            (evidence.analysis_json or {}).get("hosting_provider"),
            (evidence.analysis_json or {}).get("edge_provider"),
        ]
        try:
            infra = (evidence.analysis_json or {}).get("infrastructure") or {}
            candidates.append(infra.get("hosting_provider"))
            candidates.append(infra.get("edge_provider"))
            ns = infra.get("nameservers") or []
            ns_combined = " ".join(ns).lower() if isinstance(ns, list) else ""
            if ns_combined:
                if "cloudflare.com" in ns_combined:
                    candidates.append("cloudflare")
                if "awsdns-" in ns_combined:
                    candidates.append("aws")
                if "azure-dns" in ns_combined:
                    candidates.append("azure")
                if "google" in ns_combined or "googledomains" in ns_combined:
                    candidates.append("gcp")
                if "vercel-dns.com" in ns_combined:
                    candidates.append("vercel")
                if "netlifydns.net" in ns_combined:
                    candidates.append("netlify")
                if "shopifydns" in ns_combined:
                    candidates.append("shopify")
                if "render.com" in ns_combined:
                    candidates.append("render")
                if "njalla" in ns_combined:
                    candidates.append("njalla")
        except Exception:
            pass

        for candidate in candidates:
            canon = self._canonical_provider(candidate or "")
            if canon:
                hints.add(canon)

        haystack_parts: list[str] = []
        for item in [evidence.url] + (evidence.backend_domains or []) + (evidence.suspicious_endpoints or []):
            if isinstance(item, str):
                haystack_parts.append(item.lower())

        haystack = " ".join(haystack_parts)
        patterns: dict[str, list[str]] = {
            "digitalocean": ["ondigitalocean.app", "digitaloceanspaces.com", "digitalocean"],
            "vercel": ["vercel.app", ".vercel.com", "vercel"],
            "netlify": ["netlify.app", ".netlify.com", "netlify"],
            "render": ["onrender.com", ".render.com", "render.com"],
            "fly_io": [".fly.dev", "fly.dev"],
            "railway": ["railway.app", ".railway.app"],
            "aws": ["amazonaws.com", "cloudfront.net", ".awsstatic", "aws"],
            "gcp": ["appspot.com", "cloudfunctions.net", "googleusercontent.com", "firebaseapp.com", ".web.app", "gcp"],
            "azure": ["azurewebsites.net", "azureedge.net", "cloudapp.azure.com", "azure"],
            "cloudflare": ["workers.dev", "pages.dev", "cloudflare"],
            "fastly": ["fastly.net", ".fastly"],
            "akamai": ["akamai.net", ".akamai", "akadns.net"],
            "sucuri": ["sucuri.net", "sucuri"],
            "wix": ["wixsite.com", ".wixdns.net", "wix"],
            "squarespace": ["squarespace.com", "squarespace-cdn.com"],
            "shopify": ["myshopify.com", "shopify"],
        }
        for provider, needles in patterns.items():
            if any(needle in haystack for needle in needles):
                hints.add(provider)

        return {h for h in hints if h}

    def _collect_service_hints(self, evidence: ReportEvidence) -> set[str]:
        """Detect platform-specific service usage (e.g., Telegram bots, Discord webhooks)."""
        hints: set[str] = set()
        haystack_parts: list[str] = []
        for item in [evidence.url] + (evidence.backend_domains or []) + (evidence.suspicious_endpoints or []):
            if isinstance(item, str):
                haystack_parts.append(item.lower())
        haystack = " ".join(haystack_parts)

        if any(token in haystack for token in ["t.me/", "telegram.me", "telegram.org", "telegram"]):
            hints.add("telegram")
        if any(token in haystack for token in ["discord.gg", "discord.com", "discordapp.com", "discordapp.net", "discordapp.io"]):
            hints.add("discord")
        return hints

    async def _collect_hosting_hints_async(self, evidence: ReportEvidence) -> set[str]:
        """
        Async wrapper to enrich hosting hints with lightweight live probes.

        This keeps the base heuristic fast while adding selective checks
        (e.g., Vercel headers/CNAME IPs) without blocking the event loop.
        """
        hints = self._collect_hosting_hints(evidence)
        if "vercel" in hints:
            return hints

        candidates = self._provider_host_candidates(evidence)
        if not candidates:
            return hints

        try:
            extra = await asyncio.to_thread(self._detect_vercel_from_hosts, candidates)
            hints.update(extra)
        except Exception as e:
            logger.debug("Provider host probe failed for %s: %s", evidence.domain, e)

        return hints

    async def _detect_registrar_hint(self, evidence: ReportEvidence) -> tuple[Optional[str], Optional[str]]:
        """Best-effort registrar lookup using cached analysis or RDAP."""
        registrar = None
        abuse_email = None
        try:
            registrar = (evidence.analysis_json or {}).get("registrar")
            infra = (evidence.analysis_json or {}).get("infrastructure") or {}
            registrar = registrar or infra.get("registrar")
            abuse_email = infra.get("registrar_abuse_email")
        except Exception:
            pass

        if not registrar and not abuse_email:
            try:
                from .rdap import lookup_registrar_via_rdap

                lookup = await lookup_registrar_via_rdap(evidence.domain)
                registrar = lookup.registrar_name
                abuse_email = lookup.abuse_email
            except Exception as e:
                logger.debug("RDAP lookup failed for %s: %s", evidence.domain, e)

        return self._normalize_hint(registrar), abuse_email

    @staticmethod
    def _registrar_platforms_for(registrar_name: Optional[str]) -> set[str]:
        """Map registrar names to specific platform reporters."""
        name = (registrar_name or "").lower()
        if not name:
            return set()
        mapping = {
            "godaddy": "godaddy",
            "namecheap": "namecheap",
            "porkbun": "porkbun",
            "tucows": "tucows",
            "hover": "tucows",
            "google": "google_domains",
            "njalla": "njalla",
        }
        return {platform for needle, platform in mapping.items() if needle in name}

    def _platform_applicable(
        self,
        platform: str,
        reporter: BaseReporter,
        evidence: ReportEvidence,
        hosting_hints: set[str],
        registrar_name: Optional[str],
        registrar_matches: set[str],
        service_hints: set[str],
        registrar_abuse_email: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Determine whether a reporter is relevant for the given evidence."""
        is_applicable, reason = reporter.is_applicable(evidence)
        if not is_applicable:
            return False, reason

        hosting_specific = {
            "digitalocean",
            "aws",
            "gcp",
            "azure",
            "vercel",
            "netlify",
            "render",
            "fly_io",
            "railway",
            "cloudflare",
            "fastly",
            "akamai",
            "sucuri",
            "wix",
            "squarespace",
            "shopify",
            "njalla",
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

        if platform in hosting_specific:
            if platform in {"hosting_provider", "edge_provider", "dns_provider"}:
                label = getattr(reporter, "provider_label", "provider").lower()
                return (is_applicable, reason or f"No {label} identified")
            if platform == "digitalocean":
                if is_applicable or platform in hosting_hints:
                    return True, ""
                return False, "No DigitalOcean infrastructure detected"
            return (platform in hosting_hints, f"Not hosted on {platform}")

        if platform in registrar_specific:
            has_registrar_signal = bool(registrar_name or registrar_abuse_email)
            if platform == "registrar":
                return (has_registrar_signal, "Registrar not identified")
            return (platform in registrar_matches, f"Registrar not matched: {registrar_name or 'unknown'}")

        if platform in service_specific:
            return (platform in service_hints, f"No {platform} endpoints detected")

        return True, ""

    async def _detect_registrar_hint(self, evidence: ReportEvidence) -> tuple[Optional[str], Optional[str]]:
        """Best-effort registrar lookup using cached analysis or RDAP."""
        registrar = None
        abuse_email = None
        try:
            registrar = (evidence.analysis_json or {}).get("registrar")
            infra = (evidence.analysis_json or {}).get("infrastructure") or {}
            registrar = registrar or infra.get("registrar")
            abuse_email = infra.get("registrar_abuse_email")
        except Exception:
            pass

        if not registrar and not abuse_email:
            try:
                from .rdap import lookup_registrar_via_rdap

                lookup = await lookup_registrar_via_rdap(evidence.domain)
                registrar = lookup.registrar_name
                abuse_email = lookup.abuse_email
            except Exception as e:
                logger.debug(f"RDAP lookup failed for {evidence.domain}: {e}")

        return self._normalize_hint(registrar), abuse_email

    @staticmethod
    def _registrar_platforms_for(registrar_name: Optional[str]) -> set[str]:
        """Map registrar names to specific platform reporters."""
        name = (registrar_name or "").lower()
        if not name:
            return set()
        mapping = {
            "godaddy": "godaddy",
            "namecheap": "namecheap",
            "porkbun": "porkbun",
            "tucows": "tucows",
            "hover": "tucows",
            "google": "google_domains",
            "njalla": "njalla",
        }
        return {platform for needle, platform in mapping.items() if needle in name}

    def _platform_applicable(
        self,
        platform: str,
        reporter: BaseReporter,
        evidence: ReportEvidence,
        hosting_hints: set[str],
        registrar_name: Optional[str],
        registrar_matches: set[str],
        service_hints: set[str],
        registrar_abuse_email: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Determine whether a reporter is relevant for the given evidence."""
        is_applicable, reason = reporter.is_applicable(evidence)
        if not is_applicable:
            return False, reason

        hosting_specific = {
            "digitalocean",
            "aws",
            "gcp",
            "azure",
            "vercel",
            "netlify",
            "render",
            "fly_io",
            "railway",
            "cloudflare",
            "fastly",
            "akamai",
            "sucuri",
            "wix",
            "squarespace",
            "shopify",
            "njalla",
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

        if platform in hosting_specific:
            if platform in {"hosting_provider", "edge_provider", "dns_provider"}:
                label = getattr(reporter, "provider_label", "provider").lower()
                return (is_applicable, reason or f"No {label} identified")
            if platform == "digitalocean":
                if is_applicable or platform in hosting_hints:
                    return True, ""
                return False, "No DigitalOcean infrastructure detected"
            return (platform in hosting_hints, f"Not hosted on {platform}")

        if platform in registrar_specific:
            has_registrar_signal = bool(registrar_name or registrar_abuse_email)
            if platform == "registrar":
                return (has_registrar_signal, "Registrar not identified")
            return (platform in registrar_matches, f"Registrar not matched: {registrar_name or 'unknown'}")

        if platform in service_specific:
            return (platform in service_hints, f"No {platform} endpoints detected")

        return True, ""
