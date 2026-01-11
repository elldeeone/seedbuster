"""Browser analyzer redirect helpers."""

from __future__ import annotations

from typing import Optional
from urllib.parse import urljoin

from playwright.async_api import Response

from .browser_constants import (
    REDIRECT_STATUS_CODES,
    _extract_meta_refresh_url,
    _normalize_url_for_compare,
)
from .browser_models import BrowserResult


class BrowserRedirectMixin:
    """Redirect chain helpers."""

    @staticmethod
    async def _build_redirect_chain(response: Optional[Response]) -> list[dict]:
        chain: list[dict] = []
        if not response:
            return chain
        try:
            req = response.request
            redirects: list[dict] = []
            while req:
                resp = await req.response()
                if resp and resp.status in REDIRECT_STATUS_CODES:
                    headers = resp.headers or {}
                    location = headers.get("location")
                    header_subset = {}
                    for key in ("server", "x-powered-by", "x-vercel-id"):
                        value = headers.get(key)
                        if value:
                            header_subset[key] = value
                    to_url = urljoin(req.url, location) if location else None
                    redirects.append(
                        {
                            "type": "http",
                            "status": resp.status,
                            "method": req.method,
                            "from_url": req.url,
                            "to_url": to_url,
                            "location": location,
                            "headers": header_subset or None,
                        }
                    )
                req = req.redirected_from
            chain = list(reversed(redirects))
        except Exception:
            return []
        return chain

    @staticmethod
    def _dedupe_redirect_chain(chain: list[dict]) -> list[dict]:
        deduped: list[dict] = []
        seen: set[str] = set()

        def _key(entry: dict) -> str:
            return (
                f"{_normalize_url_for_compare(str(entry.get('from_url') or ''))}"
                f">{_normalize_url_for_compare(str(entry.get('to_url') or ''))}"
                f":{entry.get('type')}"
            )

        for entry in chain:
            if not isinstance(entry, dict):
                continue
            key = _key(entry)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(entry)
        return deduped

    @staticmethod
    def _augment_redirect_chain(result: BrowserResult) -> None:
        chain = list(result.redirect_chain or [])

        def _key(entry: dict) -> str:
            return (
                f"{_normalize_url_for_compare(str(entry.get('from_url') or ''))}"
                f">{_normalize_url_for_compare(str(entry.get('to_url') or ''))}"
                f":{entry.get('type')}"
            )

        seen = {_key(entry) for entry in chain}

        if result.html_early:
            meta_url = _extract_meta_refresh_url(result.html_early)
            if meta_url:
                base_url = result.early_url or result.initial_url or ""
                resolved = urljoin(base_url, meta_url) if base_url else meta_url
                entry = {
                    "type": "meta",
                    "from_url": base_url or None,
                    "to_url": resolved,
                }
                if _key(entry) not in seen:
                    chain.append(entry)
                    seen.add(_key(entry))

        if result.early_url and result.final_url:
            early_norm = _normalize_url_for_compare(result.early_url)
            final_norm = _normalize_url_for_compare(result.final_url)
            if early_norm and final_norm and early_norm != final_norm:
                entry = {
                    "type": "js",
                    "from_url": result.early_url,
                    "to_url": result.final_url,
                }
                if _key(entry) not in seen:
                    chain.append(entry)
                    seen.add(_key(entry))

        result.redirect_chain = chain
        result.redirect_hops = len(chain)
        result.redirect_detected = bool(chain)
