import pytest

from src.analyzer.takedown_checker import TakedownChecker, TakedownStatus


def _base_dns():
    return {"resolves": True, "addresses": ["203.0.113.10"], "is_sinkholed": False}


def _base_http(**overrides):
    base = {"status": 200, "error": None, "hash": None, "text": "", "headers": {}}
    base.update(overrides)
    return base


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


class _FakeAsyncClient:
    def __init__(self, outcomes: list[object]):
        self._outcomes = outcomes

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url: str):
        if not self._outcomes:
            raise RuntimeError("No outcomes configured")
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return _FakeResponse(int(outcome))


def test_cloudflare_origin_dns_error_marks_confirmed_down():
    checker = TakedownChecker()
    result = checker._analyze(
        "kaspanet.app",
        _base_dns(),
        _base_http(
            status=530,
            text="error code: 1016",
            headers={"server": "cloudflare"},
        ),
        None,
        None,
    )

    assert result.status == TakedownStatus.CONFIRMED_DOWN
    assert result.provider_signal == "cloudflare:1016"


def test_vercel_deployment_not_found_marks_confirmed_down():
    checker = TakedownChecker()
    result = checker._analyze(
        "app-kaspa-ng.org",
        _base_dns(),
        _base_http(
            status=404,
            text="The deployment could not be found on Vercel. DEPLOYMENT_NOT_FOUND",
            headers={"server": "Vercel", "x-vercel-error": "DEPLOYMENT_NOT_FOUND"},
        ),
        None,
        None,
    )

    assert result.status == TakedownStatus.CONFIRMED_DOWN
    assert result.provider_signal == "vercel:deployment_not_found"


def test_cloudflare_dns_error_marks_confirmed_down():
    checker = TakedownChecker()
    result = checker._analyze(
        "kaspawallet.net",
        _base_dns(),
        _base_http(
            status=409,
            text="error code: 1001",
            headers={"server": "cloudflare"},
        ),
        None,
        None,
    )

    assert result.status == TakedownStatus.CONFIRMED_DOWN
    assert result.provider_signal == "cloudflare:1001"


def test_backend_500_marks_likely_down():
    checker = TakedownChecker()
    result = checker._analyze(
        "wallet-kaspa.net",
        _base_dns(),
        _base_http(status=200),
        {"status": 503, "error": None, "target": "https://api.wallet-kaspa.net/"},
        None,
    )

    assert result.status == TakedownStatus.LIKELY_DOWN
    assert result.provider_signal == "backend:503"


def test_parking_page_marks_likely_down():
    checker = TakedownChecker()
    result = checker._analyze(
        "kaspawallet.org",
        _base_dns(),
        _base_http(status=200, text="This domain is for sale on Sedo."),
        None,
        None,
    )

    assert result.status == TakedownStatus.LIKELY_DOWN
    assert result.provider_signal == "parking:for_sale"


@pytest.mark.asyncio
async def test_backend_error_only_when_all_fail(monkeypatch):
    import httpx

    def fake_async_client(*args, **kwargs):
        return _FakeAsyncClient([OSError("dns error"), 200])

    monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)
    checker = TakedownChecker()
    result = await checker._check_backend(
        "walletkaspanet.com",
        {"status": 200, "final_url": "https://www.walletkaspanet.com"},
        ["walrus-app-o5hvw.ondigitalocean.app", "kaspa-backend.vercel.app"],
    )

    assert result["status"] == 200
    assert result["error"] is None


@pytest.mark.asyncio
async def test_backend_error_when_all_candidates_fail(monkeypatch):
    import httpx

    def fake_async_client(*args, **kwargs):
        return _FakeAsyncClient([OSError("dns error"), OSError("dns error 2")])

    monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)
    checker = TakedownChecker()
    result = await checker._check_backend(
        "walletkaspanet.com",
        {"status": 200, "final_url": "https://www.walletkaspanet.com"},
        ["walrus-app-o5hvw.ondigitalocean.app", "kaspa-backend.vercel.app"],
    )

    assert result["status"] is None
    assert result["error"]
    assert result["target"].startswith("https://walrus-app-o5hvw.ondigitalocean.app")
