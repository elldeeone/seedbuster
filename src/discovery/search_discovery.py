"""Search-engine based discovery (via official APIs, not SERP scraping)."""

from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Set
from urllib.parse import urlparse

import aiohttp
import tldextract

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SearchResult:
    """Single search result entry."""

    url: str
    title: str | None = None
    snippet: str | None = None


class SearchProvider(Protocol):
    """Search provider interface."""

    async def search(self, query: str, max_results: int, *, start: int = 1) -> list[SearchResult]:
        raise NotImplementedError

    async def close(self) -> None:
        return


class GoogleCSEProvider:
    """Google Programmable Search Engine (Custom Search JSON API) provider."""

    def __init__(self, api_key: str, cse_id: str, *, gl: str = "", hl: str = "en"):
        self._api_key = api_key
        self._cse_id = cse_id
        self._gl = gl
        self._hl = hl
        self._session: aiohttp.ClientSession | None = None

    async def search(self, query: str, max_results: int, *, start: int = 1) -> list[SearchResult]:
        # API limits: num <= 10, start is 1-indexed, max 100 results.
        max_results = max(0, min(int(max_results), 100))
        if max_results == 0:
            return []

        session = await self._get_session()
        results: list[SearchResult] = []
        start = max(1, min(int(start), 100))

        while len(results) < max_results:
            max_num_by_start = 100 - start + 1
            if max_num_by_start <= 0:
                break
            num = min(10, max_results - len(results), max_num_by_start)
            if num <= 0:
                break
            params: dict[str, str | int] = {
                "key": self._api_key,
                "cx": self._cse_id,
                "q": query,
                "num": num,
                "start": start,
            }
            if self._gl:
                params["gl"] = self._gl
            if self._hl:
                params["hl"] = self._hl

            async with session.get(
                "https://www.googleapis.com/customsearch/v1",
                params=params,
                timeout=15,
            ) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"Google CSE HTTP {resp.status}: {text[:200]}")
                data = await resp.json()

            items = data.get("items") or []
            if not items:
                break

            for item in items:
                url = item.get("link")
                if not url:
                    continue
                results.append(
                    SearchResult(
                        url=url,
                        title=item.get("title"),
                        snippet=item.get("snippet"),
                    )
                )

            if len(items) < num:
                break
            start += num
            if start > 100:
                break

        return results

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()


class BingWebSearchProvider:
    """Bing Web Search API provider."""

    def __init__(self, api_key: str, *, endpoint: str, market: str = "en-US"):
        self._api_key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._market = market
        self._session: aiohttp.ClientSession | None = None

    async def search(self, query: str, max_results: int, *, start: int = 1) -> list[SearchResult]:
        # API allows count up to 50 per request.
        max_results = max(0, int(max_results))
        if max_results == 0:
            return []

        session = await self._get_session()
        results: list[SearchResult] = []
        offset = max(0, int(start) - 1)

        while len(results) < max_results:
            count = min(50, max_results - len(results))
            headers = {"Ocp-Apim-Subscription-Key": self._api_key}
            params = {
                "q": query,
                "count": str(count),
                "offset": str(offset),
                "mkt": self._market,
                "responseFilter": "Webpages",
            }
            async with session.get(self._endpoint, headers=headers, params=params, timeout=15) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    raise RuntimeError(f"Bing search HTTP {resp.status}: {text[:200]}")
                data = await resp.json()

            items = ((data.get("webPages") or {}).get("value")) or []
            if not items:
                break

            for item in items:
                url = item.get("url")
                if not url:
                    continue
                results.append(
                    SearchResult(
                        url=url,
                        title=item.get("name"),
                        snippet=item.get("snippet"),
                    )
                )

            if len(items) < count:
                break
            offset += count

        return results

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()


def _is_interesting_path(pathish: str) -> bool:
    lowered = pathish.lower()
    keywords = (
        "wallet",
        "recover",
        "restore",
        "seed",
        "mnemonic",
        "phrase",
        "import",
        "login",
        "connect",
        "claim",
        "airdrop",
        "verify",
        "unlock",
    )
    return any(k in lowered for k in keywords)


def _registered_domain(hostname: str) -> str:
    extracted = tldextract.extract(hostname)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return hostname.lower()


def normalize_search_target(url: str) -> tuple[str, str] | None:
    """
    Convert a search result URL into (hostname, target) used by the pipeline.

    Target is in the same format as /submit: no scheme, optional path/query/fragment.
    """
    raw = (url or "").strip()
    if not raw:
        return None
    if raw.startswith(("mailto:", "javascript:", "data:")):
        return None

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if parsed.scheme not in ("http", "https"):
        return None

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return None

    # Keep the route if it looks relevant (useful for SPA/hash routes).
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    rest = f"{path}{query}{fragment}"

    target = hostname
    if rest and rest != "/" and _is_interesting_path(rest):
        target = f"{hostname}{rest}"

    return hostname, target


class SearchDiscovery:
    """Periodically queries a search provider and feeds results to discovery queue."""

    def __init__(
        self,
        *,
        queue: asyncio.Queue[object],
        provider: SearchProvider,
        queries: list[str],
        interval_seconds: int,
        results_per_query: int,
        force_analyze: bool = False,
        exclude_domains: Set[str] | None = None,
        rotate_pages: bool = True,
        state_path: Path | None = None,
        max_start_index: int = 100,
    ):
        self.queue = queue
        self.provider = provider
        self.queries = [q.strip() for q in queries if q.strip()]
        self.interval_seconds = max(60, int(interval_seconds))
        self.results_per_query = max(1, int(results_per_query))
        self.force_analyze = bool(force_analyze)
        self.exclude_domains = {d.lower() for d in (exclude_domains or set())}
        self.rotate_pages = bool(rotate_pages)
        self.state_path = state_path
        self.max_start_index = max(1, int(max_start_index))
        self._query_starts: dict[str, int] = {}
        self._load_state()

        self._seen_targets: set[str] = set()
        self._seen_order: deque[str] = deque()
        self._max_seen = 20000

    def _load_state(self) -> None:
        path = self.state_path
        if not path or not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            starts = data.get("starts", {})
            if isinstance(starts, dict):
                for k, v in starts.items():
                    if isinstance(k, str) and isinstance(v, int) and v >= 1:
                        self._query_starts[k] = v
        except Exception as e:
            logger.warning("Search discovery: failed to load state from %s: %s", path, e)

    def _save_state(self) -> None:
        path = self.state_path
        if not path:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"version": 1, "starts": self._query_starts}
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning("Search discovery: failed to save state to %s: %s", path, e)

    async def run_loop(self) -> None:
        """Run discovery forever (until task cancelled)."""
        if not self.queries:
            logger.info("Search discovery enabled but no queries configured; skipping")
            return

        logger.info(
            "Search discovery started (%s, %d queries, every %ds)",
            self.provider.__class__.__name__,
            len(self.queries),
            self.interval_seconds,
        )
        try:
            while True:
                await self.run_once()
                await asyncio.sleep(self.interval_seconds)
        except asyncio.CancelledError:
            raise
        finally:
            try:
                await self.provider.close()
            except Exception:
                pass

    async def run_once(self) -> None:
        """Execute one search pass and enqueue new targets."""
        total_enqueued = 0
        for query in self.queries:
            start = 1
            if self.rotate_pages:
                try:
                    start = max(1, int(self._query_starts.get(query, 1)))
                except Exception:
                    start = 1
            total_results = 0
            excluded = 0
            duplicates = 0
            invalid = 0
            enqueued = 0

            try:
                results = await self.provider.search(query, self.results_per_query, start=start)
                total_results = len(results)
            except Exception as e:
                logger.warning("Search discovery query failed (%s): %s", query, e)
                continue

            for result in results:
                normalized = normalize_search_target(result.url)
                if not normalized:
                    invalid += 1
                    continue
                hostname, target = normalized

                # Drop obvious false positives (forums/social/video/docs).
                registered = _registered_domain(hostname)
                if registered in self.exclude_domains or hostname in self.exclude_domains:
                    excluded += 1
                    continue

                if target in self._seen_targets:
                    duplicates += 1
                    continue

                self._seen_targets.add(target)
                self._seen_order.append(target)
                if len(self._seen_targets) > self._max_seen:
                    # Evict oldest in FIFO order.
                    while len(self._seen_order) > self._max_seen:
                        oldest = self._seen_order.popleft()
                        self._seen_targets.discard(oldest)

                try:
                    self.queue.put_nowait(
                        {
                            "domain": target,
                            "source": "search",
                            "force": self.force_analyze,
                        }
                    )
                    enqueued += 1
                    total_enqueued += 1
                except asyncio.QueueFull:
                    logger.warning("Discovery queue full, dropping search hit: %s", target)
                    return

            logger.info(
                "Search discovery: %r (start=%d) -> %d results, %d enqueued (%d excluded, %d dup, %d invalid)",
                query,
                start,
                total_results,
                enqueued,
                excluded,
                duplicates,
                invalid,
            )

            if self.rotate_pages:
                next_start = start + self.results_per_query
                if next_start > self.max_start_index:
                    next_start = 1
                self._query_starts[query] = next_start
                self._save_state()

        if total_enqueued == 0:
            logger.info("Search discovery: pass complete (no new targets)")
