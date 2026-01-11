"""Domain/URL normalization utilities."""

from __future__ import annotations

from urllib.parse import urlparse

import re

import tldextract


_URL_RE = re.compile(r"https?://\S+")
_URL_TRAIL_ALLOWED = re.compile(r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]")


def ensure_url(value: str) -> str:
    """Ensure a URL has a scheme for reliable parsing."""
    raw = (value or "").strip()
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        return raw
    return f"https://{raw}"


def extract_hostname(value: str) -> str:
    """Extract a hostname from a URL/domain input (best-effort)."""
    raw = (value or "").strip()
    if not raw:
        return ""
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    hostname = (parsed.hostname or raw.split("/")[0]).strip().lower()
    return hostname.strip(".")


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


def extract_first_url(text: str) -> str | None:
    """Extract the first URL from text (best-effort)."""
    raw = (text or "").strip()
    if not raw:
        return None
    match = _URL_RE.search(raw)
    if not match:
        return None
    candidate = match.group(0).rstrip(").,]}>\"'")
    while candidate and not _URL_TRAIL_ALLOWED.match(candidate[-1]):
        candidate = candidate[:-1]
    return candidate or None


def normalize_source_url(source_url: str | None, *, canonical: str | None = None) -> str | None:
    """Normalize a source URL and optionally enforce same-domain constraints."""
    raw = (source_url or "").strip()
    if not raw:
        return None

    candidate = extract_first_url(raw) or raw.split()[0]
    candidate = candidate.rstrip(").,]}>\"'")
    while candidate and not _URL_TRAIL_ALLOWED.match(candidate[-1]):
        candidate = candidate[:-1]
    if not candidate:
        return None

    if not candidate.startswith(("http://", "https://")):
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    if canonical and canonicalize_domain(parsed.netloc) != canonicalize_domain(canonical):
        return None

    return candidate


def strip_port(host: str) -> str:
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
    host = strip_port(host)
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
    host = strip_port(host)
    if host in allowlist:
        return True
    registered = registered_domain(host)
    return registered in allowlist
