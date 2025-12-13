"""Tests for search-engine discovery helpers."""

import asyncio

import pytest

from src.discovery.search_discovery import SearchDiscovery, SearchResult, normalize_search_target


def test_normalize_search_target_skips_non_http():
    assert normalize_search_target("mailto:test@example.com") is None
    assert normalize_search_target("javascript:alert(1)") is None


def test_normalize_search_target_basic_and_interesting_paths():
    assert normalize_search_target("https://example.com/") == ("example.com", "example.com")
    assert normalize_search_target("example.com/wallet") == ("example.com", "example.com/wallet")
    assert normalize_search_target("https://example.com/#/recover") == (
        "example.com",
        "example.com/#/recover",
    )


class _StubProvider:
    def __init__(self, results: list[SearchResult]):
        self._results = results
        self.calls: list[tuple[str, int]] = []

    async def search(self, query: str, max_results: int) -> list[SearchResult]:
        self.calls.append((query, max_results))
        return self._results

    async def close(self) -> None:
        return


@pytest.mark.asyncio
async def test_search_discovery_enqueues_results():
    queue: asyncio.Queue[object] = asyncio.Queue(maxsize=10)
    provider = _StubProvider(
        [
            SearchResult(url="https://www.reddit.com/r/kaspa/comments/123/recover_wallet_seed/"),
            SearchResult(url="https://phish.example/wallet"),
            SearchResult(url="https://phish.example/wallet"),  # duplicate
            SearchResult(url="https://safe.example/"),
        ]
    )

    discovery = SearchDiscovery(
        queue=queue,
        provider=provider,
        queries=["kaspa wallet"],
        interval_seconds=3600,
        results_per_query=10,
        force_analyze=True,
        exclude_domains={"reddit.com"},
    )

    await discovery.run_once()

    first = queue.get_nowait()
    second = queue.get_nowait()
    assert queue.empty()

    assert first == {"domain": "phish.example/wallet", "source": "search", "force": True}
    assert second == {"domain": "safe.example", "source": "search", "force": True}
    assert provider.calls == [("kaspa wallet", 10)]
