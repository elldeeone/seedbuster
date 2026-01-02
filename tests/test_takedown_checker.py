from src.analyzer.takedown_checker import TakedownChecker, TakedownStatus


def _base_dns():
    return {"resolves": True, "addresses": ["203.0.113.10"], "is_sinkholed": False}


def _base_http(**overrides):
    base = {"status": 200, "error": None, "hash": None, "text": "", "headers": {}}
    base.update(overrides)
    return base


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
