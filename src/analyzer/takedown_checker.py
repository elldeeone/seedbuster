"""Lightweight takedown checker to detect when phishing sites go offline."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Optional
import httpx


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


class TakedownChecker:
    """Perform DNS/HTTP probes to estimate takedown status."""

    async def check_domain(self, domain: str) -> TakedownCheckResult:
        dns_result = await self._check_dns(domain)
        http_result = await self._check_http(domain)
        return self._analyze(domain, dns_result, http_result)

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
                return {"status": resp.status_code, "error": None}
        except Exception as e:
            # Fall back to HTTP if HTTPS failed outright
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                    resp = await client.get(f"http://{domain}")
                    return {"status": resp.status_code, "error": str(e)}
            except Exception as e2:
                return {"status": None, "error": str(e2) or str(e)}

    def _analyze(self, domain: str, dns: dict, http: dict) -> TakedownCheckResult:
        confidence = 0.0

        dns_resolves = bool(dns.get("resolves"))
        dns_addresses = dns.get("addresses") or []
        dns_error = dns.get("error")
        is_sinkholed = bool(dns.get("is_sinkholed"))

        http_status = http.get("status")
        http_error = http.get("error")

        if not dns_resolves:
            confidence += 0.6
        if is_sinkholed:
            confidence = max(confidence, 0.9)

        if http_status in (404, 410):
            confidence += 0.3
        elif http_status in (500, 503, 522, 523, 524):
            confidence += 0.15
        elif http_status is None:
            confidence += 0.2

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
        )
