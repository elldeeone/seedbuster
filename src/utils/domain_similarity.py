"""Domain similarity helpers shared across campaign detection and dashboard UI."""

from __future__ import annotations

import tldextract

from .domains import extract_hostname

DOMAIN_SIMILARITY_THRESHOLD = 0.82
DOMAIN_SIMILARITY_MIN_LEN = 6
DOMAIN_SIMILARITY_LIMIT = 6

MULTITENANT_SUFFIXES = (
    "webflow.io",
    "vercel.app",
    "netlify.app",
    "github.io",
    "pages.dev",
    "web.app",
    "herokuapp.com",
    "azurewebsites.net",
)


def strip_domain_label(label: str) -> str:
    return "".join(ch for ch in label.lower() if ch.isalnum())


def domain_similarity_key_from_host(host: str) -> str:
    raw = (host or "").strip().lower().strip(".")
    if not raw:
        return ""

    for suffix in MULTITENANT_SUFFIXES:
        suffix_dot = f".{suffix}"
        if raw == suffix:
            return ""
        if raw.endswith(suffix_dot):
            label = raw[: -len(suffix_dot)]
            return strip_domain_label(label)

    extracted = tldextract.extract(raw)
    if extracted.domain:
        return strip_domain_label(extracted.domain)

    return strip_domain_label(raw.split(".")[0])


def domain_similarity_key(domain: str) -> str:
    """Compute a similarity key from a raw domain/URL input."""
    host = extract_hostname(domain)
    return domain_similarity_key_from_host(host)
