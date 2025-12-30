"""Domain normalization utilities."""

from __future__ import annotations

from urllib.parse import urlparse

import tldextract


def canonicalize_domain(value: str) -> str:
    """
    Normalize a domain/URL to a canonical host key.

    - Lowercase
    - Strip leading "www."
    - Preserve port (if present)
    - Ignore path/query/fragment
    """
    raw = (value or "").strip()
    if not raw:
        return ""

    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or raw.split("/")[0]).strip().lower().strip(".")
    if not host:
        return ""

    if host.startswith("www.") and len(host) > 4:
        host = host[4:]

    port = parsed.port
    if port:
        host = f"{host}:{port}"

    return host


def _strip_port(host: str) -> str:
    if not host:
        return ""
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def registered_domain(value: str) -> str:
    """Return the registrable domain for a host or URL (best-effort)."""
    host = canonicalize_domain(value)
    if not host:
        return ""
    host = _strip_port(host)
    extracted = tldextract.extract(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return host.lower()


def normalize_allowlist_domain(value: str) -> str:
    """Normalize allowlist entries to registrable domain (includes all subdomains)."""
    return registered_domain(value)


def allowlist_contains(domain: str, allowlist: set[str]) -> bool:
    """Check if a domain matches the allowlist (registrable domain + subdomains)."""
    if not allowlist:
        return False
    host = canonicalize_domain(domain)
    if not host:
        return False
    host = _strip_port(host)
    if host in allowlist:
        return True
    registered = registered_domain(host)
    return registered in allowlist
