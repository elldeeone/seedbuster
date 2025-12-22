"""Domain normalization utilities."""

from __future__ import annotations

from urllib.parse import urlparse


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
