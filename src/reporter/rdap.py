"""RDAP helpers for registrar lookups.

Used by manual and email reporters to find registrar names and abuse contacts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RdapLookupResult:
    registrar_name: Optional[str]
    abuse_email: Optional[str]
    rdap_url: str
    status_values: Optional[list[str]] = None
    error: Optional[str] = None
    status_code: Optional[int] = None

    @property
    def ok(self) -> bool:
        return self.error is None


def _extract_first_vcard_value(vcard_array: object, field: str) -> Optional[str]:
    """Extract first vCard value for a given field (e.g., 'fn', 'email')."""
    if not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return None
    entries = vcard_array[1]
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        if str(entry[0]).lower() != field.lower():
            continue
        value = entry[3]
        if not isinstance(value, str):
            continue
        cleaned = value.strip()
        if not cleaned:
            continue
        if field.lower() == "email" and cleaned.lower().startswith("mailto:"):
            cleaned = cleaned.split(":", 1)[-1].strip()
        return cleaned or None
    return None


def parse_registrar_and_abuse_email(data: object) -> tuple[Optional[str], Optional[str]]:
    """Return (registrar_name, abuse_email) from RDAP JSON (best-effort)."""
    if not isinstance(data, dict):
        return (None, None)

    registrar_name: Optional[str] = None
    abuse_email: Optional[str] = None

    entities = data.get("entities", [])
    if not isinstance(entities, list):
        return (None, None)

    # Prefer explicit registrar entity for name.
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles", []) or []
        if "registrar" not in roles:
            continue
        registrar_name = _extract_first_vcard_value(entity.get("vcardArray"), "fn") or registrar_name
        # Some registrars include an abuse mailbox in their vCard; grab if present.
        abuse_email = _extract_first_vcard_value(entity.get("vcardArray"), "email") or abuse_email

    # Also look for explicit abuse-role contact.
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles", []) or []
        if "abuse" not in roles:
            continue
        abuse_email = _extract_first_vcard_value(entity.get("vcardArray"), "email") or abuse_email

    return (registrar_name, abuse_email)


from ..cache import create_rdap_cache

# Module-level cache instance
_rdap_cache = create_rdap_cache(ttl_seconds=3600)


async def _fetch_rdap(url: str, timeout: float) -> RdapLookupResult:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "SeedBuster/1.0"})
    except httpx.TimeoutException:
        return RdapLookupResult(
            registrar_name=None,
            abuse_email=None,
            rdap_url=url,
            status_values=None,
            error="RDAP lookup timed out",
        )
    except Exception as e:
        return RdapLookupResult(
            registrar_name=None,
            abuse_email=None,
            rdap_url=url,
            status_values=None,
            error=f"RDAP lookup failed: {e}",
        )

    if resp.status_code != 200:
        return RdapLookupResult(
            registrar_name=None,
            abuse_email=None,
            rdap_url=url,
            status_values=None,
            error=f"RDAP lookup failed ({resp.status_code})",
            status_code=int(resp.status_code),
        )

    try:
        data = resp.json()
    except Exception:
        return RdapLookupResult(
            registrar_name=None,
            abuse_email=None,
            rdap_url=url,
            status_values=None,
            error="RDAP returned non-JSON response",
            status_code=int(resp.status_code),
        )

    registrar_name, abuse_email = parse_registrar_and_abuse_email(data)
    status_values = []
    if isinstance(data.get("status"), list):
        for entry in data["status"]:
            if isinstance(entry, str) and entry.strip():
                status_values.append(entry.strip())

    return RdapLookupResult(
        registrar_name=registrar_name,
        abuse_email=abuse_email,
        rdap_url=url,
        status_values=status_values or None,
    )


def _rdap_endpoints_for(domain: str) -> list[str]:
    """Return a list of RDAP endpoints to try (ordered)."""
    normalized = (domain or "").strip().lower()
    base = f"https://rdap.org/domain/{normalized}"
    endpoints = [base]

    # Simple TLD-based fallbacks for common zones.
    tld = ""
    if "." in normalized:
        tld = normalized.rsplit(".", 1)[-1]
    if tld in {"com", "net"}:
        endpoints.append(f"https://rdap.verisign.com/com/v1/domain/{normalized}")
    elif tld == "org":
        endpoints.append(f"https://rdap.publicinterestregistry.net/rdap/org/domain/{normalized}")

    # Generic fallback.
    endpoints.append(f"https://rdap.iana.org/domain/{normalized}")
    # Deduplicate while preserving order.
    seen = set()
    deduped: list[str] = []
    for url in endpoints:
        if url in seen:
            continue
        seen.add(url)
        deduped.append(url)
    return deduped


async def lookup_registrar_via_rdap(domain: str, *, timeout: float = 30.0, force_refresh: bool = False) -> RdapLookupResult:
    """Fetch RDAP record for a domain and extract registrar + abuse email (cached)."""
    normalized = (domain or "").strip().lower()
    if not normalized:
        rdap_url = "https://rdap.org/domain/"
        return RdapLookupResult(
            registrar_name=None,
            abuse_email=None,
            rdap_url=rdap_url,
            status_values=None,
            error="No domain provided for RDAP lookup",
        )

    # Check cache unless force refresh
    if not force_refresh:
        cached = _rdap_cache.get(normalized)
        if cached is not None:
            return cached

    endpoints = _rdap_endpoints_for(normalized)
    for url in endpoints:
        result = await _fetch_rdap(url, timeout)
        if result.ok:
            _rdap_cache.set(normalized, result)
            return result
        # Retry next endpoint on 429/503/timeout; keep last error otherwise.
        if result.status_code not in (429, 503) and "timed out" not in (result.error or ""):
            last_error = result
            break
        last_error = result

    final = last_error if 'last_error' in locals() else RdapLookupResult(
        registrar_name=None,
        abuse_email=None,
        rdap_url=endpoints[-1],
        status_values=None,
        error="RDAP lookup failed (all endpoints)",
    )
    _rdap_cache.set(normalized, final)
    return final
