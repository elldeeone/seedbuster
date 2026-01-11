"""Reporting helpers."""

from __future__ import annotations

from .domains import canonicalize_domain, ensure_url


def select_report_url(
    domain: str,
    *,
    final_url: str | None = None,
    initial_url: str | None = None,
    final_domain: str | None = None,
) -> str:
    """Select the best report URL, respecting redirect-to-kit patterns."""
    resolved_final_domain = canonicalize_domain(str(final_domain or "")) or canonicalize_domain(final_url or "")
    current_domain = canonicalize_domain(domain)
    if resolved_final_domain and current_domain and resolved_final_domain != current_domain:
        return initial_url or ensure_url(domain)
    return final_url or initial_url or ensure_url(domain)
