"""Lightweight takedown checker to detect when phishing sites go offline."""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from ..reporter.rdap import lookup_registrar_via_rdap


SINKHOLE_IPS = {"0.0.0.0", "127.0.0.1", "::1"}
SERVER_ERROR_CODES = {500, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 530}
DEFAULT_BACKEND_PROBE_PATHS = (
    "/api/health",
    "/api/status",
    "/api/ping",
    "/api",
    "/health",
    "/status",
)
MAX_BACKEND_TARGETS = 5
PROVIDER_STRONG_SIGNALS = [
    ("cloudflare:1000", 0.8, ("error code: 1000", "error 1000")),
    ("cloudflare:1001", 0.85, ("error code: 1001", "error 1001", "dns resolution error")),
    ("cloudflare:1016", 0.85, ("error code: 1016", "error 1016", "origin dns error")),
    (
        "vercel:deployment_not_found",
        0.8,
        ("deployment_not_found", "deployment could not be found on vercel"),
    ),
]
PARKING_SIGNALS = [
    (
        "parking:for_sale",
        0.6,
        ("domain for sale", "buy this domain", "this domain is for sale", "make an offer"),
    ),
    ("parking:expired", 0.6, ("domain has expired", "domain expired", "renew your domain")),
    (
        "parking:provider",
        0.6,
        ("sedo", "afternic", "dan.com", "bodis", "parkingcrew", "hugedomains"),
    ),
]


class TakedownStatus(str, Enum):
    ACTIVE = "active"
    LIKELY_DOWN = "likely_down"
    CONFIRMED_DOWN = "confirmed_down"


@dataclass
class TakedownCheckResult:
    status: TakedownStatus
    confidence: float
    http_status: Optional[int]
    http_error: Optional[str]
    dns_resolves: bool
    dns_result: Optional[str]
    is_sinkholed: bool
    domain_status: Optional[str]
    content_hash: Optional[str]
    backend_status: Optional[int]
    backend_error: Optional[str]
    backend_target: Optional[str]
    provider_signal: Optional[str]


class TakedownChecker:
    """Perform DNS/HTTP probes to estimate takedown status."""

    def __init__(
        self,
        *,
        backend_probe_paths: Optional[list[str]] = None,
        backend_status_weight: float = 0.4,
        backend_error_weight: float = 0.4,
    ) -> None:
        paths = backend_probe_paths or list(DEFAULT_BACKEND_PROBE_PATHS)
        self.backend_probe_paths = tuple([p for p in paths if p])
        self.backend_status_weight = max(0.0, min(1.0, backend_status_weight))
        self.backend_error_weight = max(0.0, min(1.0, backend_error_weight))

    async def check_domain(
        self,
        domain: str,
        *,
        previous_status: TakedownStatus | str | None = None,
        analysis: Optional[dict] = None,
    ) -> TakedownCheckResult:
        dns_task = asyncio.create_task(self._check_dns(domain))
        http_task = asyncio.create_task(self._check_http(domain))
        dns_result, http_result = await asyncio.gather(dns_task, http_task)

        backend_candidates = self._extract_backend_candidates(analysis)
        backend_result = {"status": None, "error": None, "target": None}
        if self._should_probe_backend(http_result, backend_candidates):
            backend_result = await self._check_backend(domain, http_result, backend_candidates)

        preliminary = self._analyze(domain, dns_result, http_result, backend_result, None)
        prior = self._normalize_status(previous_status)
        if self._should_check_rdap(preliminary.status, prior):
            whois_result = await self._check_rdap(domain)
            return self._analyze(domain, dns_result, http_result, backend_result, whois_result)
        return preliminary

    @staticmethod
    def _normalize_status(status: TakedownStatus | str | None) -> Optional[TakedownStatus]:
        if isinstance(status, TakedownStatus):
            return status
        if isinstance(status, str):
            value = status.strip().lower()
            for entry in TakedownStatus:
                if entry.value == value:
                    return entry
        return None

    @staticmethod
    def _should_check_rdap(
        current_status: TakedownStatus,
        previous_status: Optional[TakedownStatus],
    ) -> bool:
        if current_status in {TakedownStatus.LIKELY_DOWN, TakedownStatus.CONFIRMED_DOWN}:
            return True
        if previous_status and current_status != previous_status:
            return True
        return False

    async def _check_dns(self, domain: str) -> dict:
        loop = asyncio.get_running_loop()
        try:
            info = await loop.getaddrinfo(domain, 443)
            addrs = sorted({item[4][0] for item in info if item and len(item) >= 5})
            sinkhole = any(addr in SINKHOLE_IPS for addr in addrs)
            return {"resolves": True, "addresses": addrs, "is_sinkholed": sinkhole}
        except Exception as e:
            return {"resolves": False, "error": str(e)}

    async def _check_http(self, domain: str) -> dict:
        url = f"https://{domain}"
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                resp = await client.get(url)
                body = resp.content or b""
                body_hash = hashlib.sha256(body).hexdigest() if body else None
                headers = {key.lower(): value for key, value in resp.headers.items()}
                return {
                    "status": resp.status_code,
                    "error": None,
                    "hash": body_hash,
                    "text": (resp.text or "")[:4096],
                    "headers": headers,
                    "final_url": str(resp.url),
                    "content_type": headers.get("content-type"),
                }
        except Exception as e:
            # Fall back to HTTP if HTTPS failed outright
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                    resp = await client.get(f"http://{domain}")
                    body = resp.content or b""
                    body_hash = hashlib.sha256(body).hexdigest() if body else None
                    headers = {key.lower(): value for key, value in resp.headers.items()}
                    return {
                        "status": resp.status_code,
                        "error": str(e),
                        "hash": body_hash,
                        "text": (resp.text or "")[:4096],
                        "headers": headers,
                        "final_url": str(resp.url),
                        "content_type": headers.get("content-type"),
                    }
            except Exception as e2:
                return {
                    "status": None,
                    "error": str(e2) or str(e),
                    "hash": None,
                    "text": "",
                    "headers": {},
                    "final_url": None,
                    "content_type": None,
                }

    async def _check_rdap(self, domain: str) -> dict:
        try:
            result = await lookup_registrar_via_rdap(domain)
            if result.error:
                return {"status": None, "error": result.error}
            status = None
            if result.status_values:
                # prefer any value containing 'hold' / 'pendingDelete'
                hold = next((s for s in result.status_values if "hold" in s.lower()), None)
                status = hold or result.status_values[0]
            return {"status": status, "error": None}
        except Exception as e:
            return {"status": None, "error": str(e)}

    @staticmethod
    def _extract_backend_candidates(analysis: Optional[dict]) -> list[str]:
        if not analysis or not isinstance(analysis, dict):
            return []
        candidates: list[str] = []
        for value in analysis.get("backend_domains") or []:
            if isinstance(value, str):
                cleaned = value.strip()
                if cleaned:
                    candidates.append(cleaned)
        for value in analysis.get("suspicious_endpoints") or []:
            if isinstance(value, str):
                cleaned = value.strip()
                if cleaned:
                    candidates.append(cleaned)
        return candidates[:20]

    @staticmethod
    def _should_probe_backend(http: dict, backend_candidates: list[str]) -> bool:
        status = http.get("status")
        if status is None or status >= 400:
            return False
        if backend_candidates:
            return True
        content_type = (http.get("content_type") or "").lower()
        if not content_type:
            return True
        if "text/html" in content_type or "application/json" in content_type:
            return True
        if content_type.startswith("text/"):
            return True
        return False

    async def _check_backend(self, domain: str, http: dict, backend_candidates: list[str]) -> dict:
        targets = self._build_backend_targets(domain, http, backend_candidates)
        if not targets:
            return {"status": None, "error": None, "target": None}

        timeout = httpx.Timeout(8, connect=5)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            first_response = None
            first_server_error = None
            first_error = None
            first_error_target = None
            for url in targets:
                try:
                    resp = await client.get(url)
                    status = resp.status_code
                    if status >= 500:
                        if first_server_error is None:
                            first_server_error = {"status": status, "error": None, "target": url}
                        continue
                    if first_response is None:
                        first_response = {"status": status, "error": None, "target": url}
                except Exception as exc:
                    if first_error is None:
                        first_error = str(exc)
                        first_error_target = url
                    continue

        if first_response is not None:
            return first_response
        if first_server_error is not None:
            return first_server_error
        if first_error is not None:
            return {"status": None, "error": first_error, "target": first_error_target}
        return {"status": None, "error": None, "target": None}

    def _build_backend_targets(
        self,
        domain: str,
        http: dict,
        backend_candidates: list[str],
    ) -> list[str]:
        base_url = self._resolve_base_url(domain, http)
        targets: list[str] = []

        for candidate in backend_candidates:
            targets.extend(self._normalize_backend_candidate(candidate, base_url))

        if not targets:
            for path in self.backend_probe_paths:
                targets.append(urljoin(f"{base_url}/", path.lstrip("/")))
            targets.extend(
                self._extract_backend_urls(http.get("text") or "", base_url, domain)
            )

        return self._dedupe_targets(targets)[:MAX_BACKEND_TARGETS]

    @staticmethod
    def _resolve_base_url(domain: str, http: dict) -> str:
        final_url = http.get("final_url") or ""
        parsed = urlparse(final_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        return f"https://{domain}"

    @staticmethod
    def _normalize_backend_candidate(candidate: str, base_url: str) -> list[str]:
        raw = (candidate or "").strip()
        if not raw:
            return []
        if raw.startswith("//"):
            raw = f"https:{raw}"
        if raw.startswith("/"):
            return [urljoin(f"{base_url}/", raw.lstrip("/"))]
        if "://" not in raw:
            raw = f"https://{raw}"
        parsed = urlparse(raw)
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            return []
        if not parsed.netloc:
            return []
        host = (parsed.hostname or "").lower()
        if not host or host in SINKHOLE_IPS or host == "localhost":
            return []
        if "." not in host:
            return []
        if not parsed.path:
            return [f"{parsed.scheme}://{parsed.netloc}/"]
        return [raw]

    def _extract_backend_urls(self, text: str, base_url: str, domain: str) -> list[str]:
        if not text:
            return []
        domain_lower = domain.lower()
        matches: set[str] = set()

        for match in re.findall(r"https?://[^\"'\\s)]+", text):
            parsed = urlparse(match)
            host = (parsed.hostname or "").lower()
            if host and self._host_matches_domain(host, domain_lower):
                matches.add(match)

        for match in re.findall(r"//[^\"'\\s)]+", text):
            candidate = f"https:{match}"
            parsed = urlparse(candidate)
            host = (parsed.hostname or "").lower()
            if host and self._host_matches_domain(host, domain_lower):
                matches.add(candidate)

        for match in re.findall(r"['\"](/api/[^'\"]+)['\"]", text):
            matches.add(urljoin(f"{base_url}/", match.lstrip("/")))

        return list(matches)

    @staticmethod
    def _host_matches_domain(host: str, domain: str) -> bool:
        if host == domain:
            return True
        return host.endswith(f".{domain}")

    @staticmethod
    def _dedupe_targets(targets: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for target in targets:
            if target in seen:
                continue
            seen.add(target)
            deduped.append(target)
        return deduped

    def _analyze(
        self,
        domain: str,
        dns: dict,
        http: dict,
        backend: dict,
        whois: Optional[dict],
    ) -> TakedownCheckResult:
        confidence = 0.0

        dns_resolves = bool(dns.get("resolves"))
        dns_addresses = dns.get("addresses") or []
        dns_error = dns.get("error")
        is_sinkholed = bool(dns.get("is_sinkholed"))

        http_status = http.get("status")
        http_error = http.get("error")
        http_text = (http.get("text") or "").lower()
        content_hash = http.get("hash")
        backend_status = backend.get("status") if backend else None
        backend_error = backend.get("error") if backend else None
        backend_target = backend.get("target") if backend else None
        http_headers = http.get("headers") or {}
        server_header = str(http_headers.get("server") or "").lower()
        vercel_error = str(http_headers.get("x-vercel-error") or "").lower().strip()
        provider_signal = None
        signal_confidence = 0.0

        if not dns_resolves:
            confidence += 0.6
        if is_sinkholed:
            confidence = max(confidence, 0.9)

        # Provider-specific / generic HTTP signals
        if http_status in (404, 410):
            confidence += 0.3
        elif http_status in SERVER_ERROR_CODES:
            confidence += 0.15
        elif http_status is None:
            confidence += 0.2

        # Hosting suspension patterns (best-effort)
        suspension_keywords = [
            "account suspended",
            "page not found",
            "error 1000",
            "error 1001",
            "error 1002",
            "error 1020",
            "heroku | error",
            "railway",
            "render.com",
            "vercel",
            "netlify",
        ]
        for kw in suspension_keywords:
            if kw in http_text:
                confidence += 0.2
                if signal_confidence < 0.2:
                    provider_signal = f"http:{kw}"
                    signal_confidence = 0.2
                break

        if vercel_error:
            confidence = max(confidence, 0.8)
            if signal_confidence <= 0.8:
                provider_signal = f"vercel:{vercel_error}"
                signal_confidence = 0.8

        if http_status == 530 and "cloudflare" in server_header:
            confidence = max(confidence, 0.6)
            if signal_confidence <= 0.6:
                provider_signal = "cloudflare:530"
                signal_confidence = 0.6

        for signal, weight, patterns in PROVIDER_STRONG_SIGNALS:
            if any(pattern in http_text for pattern in patterns):
                confidence = max(confidence, weight)
                if signal_confidence <= weight:
                    provider_signal = signal
                    signal_confidence = weight

        for signal, weight, patterns in PARKING_SIGNALS:
            if any(pattern in http_text for pattern in patterns):
                confidence = max(confidence, weight)
                if signal_confidence <= weight:
                    provider_signal = signal
                    signal_confidence = weight
                break

        if backend_status is not None:
            if backend_status >= 500:
                confidence += self.backend_status_weight
                if signal_confidence <= self.backend_status_weight:
                    provider_signal = f"backend:{backend_status}"
                    signal_confidence = self.backend_status_weight
        elif backend_error:
            confidence += self.backend_error_weight
            if signal_confidence <= self.backend_error_weight:
                provider_signal = "backend:error"
                signal_confidence = self.backend_error_weight

        whois_status = None
        if whois and isinstance(whois, dict):
            whois_status = whois.get("status")
            whois_error = whois.get("error")
            if whois_status and isinstance(whois_status, str) and "hold" in whois_status.lower():
                confidence += 0.4
            if whois_error:
                provider_signal = provider_signal or f"rdap_error:{whois_error}"

        if confidence >= 0.8:
            status = TakedownStatus.CONFIRMED_DOWN
        elif confidence >= 0.4:
            status = TakedownStatus.LIKELY_DOWN
        else:
            status = TakedownStatus.ACTIVE

        return TakedownCheckResult(
            status=status,
            confidence=min(confidence, 1.0),
            http_status=http_status,
            http_error=http_error,
            dns_resolves=dns_resolves,
            dns_result=",".join(dns_addresses) if dns_addresses else dns_error,
            is_sinkholed=is_sinkholed,
            domain_status=whois_status,
            content_hash=content_hash,
            backend_status=backend_status,
            backend_error=backend_error,
            backend_target=backend_target,
            provider_signal=provider_signal,
        )
