"""Lightweight takedown checker to detect when phishing sites go offline."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Optional
import httpx
import hashlib

from ..reporter.rdap import lookup_registrar_via_rdap


SINKHOLE_IPS = {"0.0.0.0", "127.0.0.1", "::1"}


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
    provider_signal: Optional[str]


class TakedownChecker:
    """Perform DNS/HTTP probes to estimate takedown status."""

    async def check_domain(
        self,
        domain: str,
        *,
        previous_status: TakedownStatus | str | None = None,
    ) -> TakedownCheckResult:
        dns_task = asyncio.create_task(self._check_dns(domain))
        http_task = asyncio.create_task(self._check_http(domain))
        dns_result, http_result = await asyncio.gather(dns_task, http_task)

        preliminary = self._analyze(domain, dns_result, http_result, None)
        prior = self._normalize_status(previous_status)
        if self._should_check_rdap(preliminary.status, prior):
            whois_result = await self._check_rdap(domain)
            return self._analyze(domain, dns_result, http_result, whois_result)
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
                return {"status": resp.status_code, "error": None, "hash": body_hash, "text": (resp.text or "")[:2048]}
        except Exception as e:
            # Fall back to HTTP if HTTPS failed outright
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                    resp = await client.get(f"http://{domain}")
                    body = resp.content or b""
                    body_hash = hashlib.sha256(body).hexdigest() if body else None
                    return {"status": resp.status_code, "error": str(e), "hash": body_hash, "text": (resp.text or "")[:2048]}
            except Exception as e2:
                return {"status": None, "error": str(e2) or str(e), "hash": None, "text": ""}

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

    def _analyze(self, domain: str, dns: dict, http: dict, whois: Optional[dict]) -> TakedownCheckResult:
        confidence = 0.0

        dns_resolves = bool(dns.get("resolves"))
        dns_addresses = dns.get("addresses") or []
        dns_error = dns.get("error")
        is_sinkholed = bool(dns.get("is_sinkholed"))

        http_status = http.get("status")
        http_error = http.get("error")
        http_text = (http.get("text") or "").lower()
        content_hash = http.get("hash")
        provider_signal = None

        if not dns_resolves:
            confidence += 0.6
        if is_sinkholed:
            confidence = max(confidence, 0.9)

        # Provider-specific / generic HTTP signals
        if http_status in (404, 410):
            confidence += 0.3
        elif http_status in (500, 503, 522, 523, 524):
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
        if http_status and http_status >= 400:
            for kw in suspension_keywords:
                if kw in http_text:
                    confidence += 0.2
                    provider_signal = f"http:{kw}"
                    break

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
            provider_signal=provider_signal,
        )
