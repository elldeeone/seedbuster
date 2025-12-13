"""Tests for external intelligence integrations."""

import pytest

from src.analyzer.external_intel import ExternalIntelligence


class _FakeResponse:
    def __init__(self, status: int, payload: dict | str):
        self.status = status
        self._payload = payload

    async def json(self):
        if not isinstance(self._payload, dict):
            raise TypeError("Response payload is not JSON")
        return self._payload

    async def text(self):
        if isinstance(self._payload, str):
            return self._payload
        return ""

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeSession:
    def __init__(
        self,
        *,
        get_payload: dict | None = None,
        get_payload_fn=None,
        post_payload: dict | None = None,
    ):
        self._get_payload = get_payload or {}
        self._get_payload_fn = get_payload_fn
        self._post_payload = post_payload or {}
        self.get_calls: list[str] = []
        self.post_calls: list[tuple[str, dict]] = []

    def get(self, url, headers=None, timeout=None):
        self.get_calls.append(url)
        if self._get_payload_fn:
            status, payload = self._get_payload_fn(url)
            return _FakeResponse(status, payload)
        return _FakeResponse(200, self._get_payload)

    def post(self, url, headers=None, json=None, timeout=None):
        self.post_calls.append((url, json or {}))
        return _FakeResponse(200, self._post_payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.mark.asyncio
async def test_query_urlscan_sets_result_url(monkeypatch):
    payload = {
        "results": [
            {
                "_id": "abc-uuid",
                "screenshot": "https://urlscan.io/screenshots/abc-uuid.png",
                "verdicts": {"overall": {"score": 0, "malicious": False, "categories": [], "brands": []}},
                "task": {"time": "2025-01-01T00:00:00.000Z"},
            }
        ]
    }

    def fake_client_session(*args, **kwargs):
        return _FakeSession(get_payload=payload)

    import aiohttp

    monkeypatch.setattr(aiohttp, "ClientSession", fake_client_session)

    intel = ExternalIntelligence(urlscan_api_key=None, cache_dir=None)
    result = await intel.query_urlscan("example.com")
    assert result.found is True
    assert result.scan_id == "abc-uuid"
    assert result.result_url == "https://urlscan.io/result/abc-uuid/"


@pytest.mark.asyncio
async def test_submit_urlscan_scan_caches_by_host(monkeypatch):
    created = {"count": 0}
    session = _FakeSession(
        post_payload={
            "uuid": "uuid1",
            "result": "https://urlscan.io/result/uuid1/",
            "api": "https://urlscan.io/api/v1/result/uuid1/",
        }
    )

    def fake_client_session(*args, **kwargs):
        created["count"] += 1
        return session

    import aiohttp

    monkeypatch.setattr(aiohttp, "ClientSession", fake_client_session)

    intel = ExternalIntelligence(urlscan_api_key="key", cache_dir=None)
    first = await intel.submit_urlscan_scan("https://example.com/")
    second = await intel.submit_urlscan_scan("https://example.com/")

    assert created["count"] == 1  # cached on second call
    assert first.submitted is True
    assert first.scan_id == "uuid1"
    assert first.result_url == "https://urlscan.io/result/uuid1/"
    assert second.result_url == first.result_url


@pytest.mark.asyncio
async def test_query_urlscan_best_prefers_scan_with_wallet_ui(monkeypatch):
    search_payload = {
        "results": [
            {
                "_id": "scan-decoy",
                "screenshot": "https://urlscan.io/screenshots/scan-decoy.png",
                "verdicts": {"overall": {"score": 0, "malicious": False, "categories": [], "brands": []}},
                "task": {"time": "2025-01-02T00:00:00.000Z"},
            },
            {
                "_id": "scan-wallet",
                "screenshot": "https://urlscan.io/screenshots/scan-wallet.png",
                "verdicts": {"overall": {"score": 0, "malicious": False, "categories": [], "brands": []}},
                "task": {"time": "2025-01-01T00:00:00.000Z"},
            },
        ]
    }

    dom_decoy = "<html><body><h1>What is Kaspa?</h1></body></html>"
    dom_wallet = "<html><body><button>Continue on Legacy Wallet</button></body></html>"

    def get_payload_fn(url: str):
        if "api/v1/search/" in url:
            # Only return results for the primary domain search.
            if "domain:www.example.com" in url:
                return 200, {"results": []}
            return 200, search_payload
        if "/dom/scan-decoy/" in url:
            return 200, dom_decoy
        if "/dom/scan-wallet/" in url:
            return 200, dom_wallet
        return 404, ""

    def fake_client_session(*args, **kwargs):
        return _FakeSession(get_payload_fn=get_payload_fn)

    import aiohttp

    monkeypatch.setattr(aiohttp, "ClientSession", fake_client_session)

    intel = ExternalIntelligence(urlscan_api_key=None, cache_dir=None)
    best = await intel.query_urlscan_best("example.com", max_results=10, max_dom_checks=8)
    assert best.found is True
    assert best.scan_id == "scan-wallet"
    assert best.result_url == "https://urlscan.io/result/scan-wallet/"
