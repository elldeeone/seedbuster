"""Tests for reporting evidence and reporter fallbacks."""

from __future__ import annotations

from datetime import datetime

import pytest

from src.reporter.base import ReportEvidence, ReportStatus
from src.reporter.cloudflare import CloudflareReporter
from src.reporter.google_form import GoogleFormReporter
from src.reporter.manager import ReportManager
from src.storage.database import Database
from src.storage.evidence import EvidenceStore


@pytest.mark.asyncio
async def test_build_evidence_uses_final_url_best_screenshot_and_derives_backends(tmp_path):
    db = Database(tmp_path / "seedbuster.db")
    await db.connect()

    target = "phish.example/#/recover"
    domain_id = await db.add_domain(domain=target, source="manual", domain_score=90)
    assert domain_id is not None

    store = EvidenceStore(tmp_path / "evidence")
    domain_dir = store.get_domain_dir(target)

    # Create screenshots: ensure the seedform shot is preferred over the main screenshot.
    seed_shot = domain_dir / "screenshot_exploration_seedform_1.png"
    seed_shot.write_bytes(b"x")
    main_shot = domain_dir / "screenshot.png"
    main_shot.write_bytes(b"y")

    await store.save_analysis(target, {
        "domain": target,
        "final_url": "https://phish.example/#/recover",
        "reasons": [
            "KNOWN MALICIOUS API key (ipdata.co): 520a83d6...",
            "Malicious URL pattern: /api/form/submit",
        ],
        "suspicious_endpoints": [
            "https://whale-app-poxe2.ondigitalocean.app/api/form/text",
            "walrus-app-o5hvw.ondigitalocean.app",
        ],
        "infrastructure": {"hosting_provider": "cloudflare"},
    })

    manager = ReportManager(database=db, evidence_store=store, enabled_platforms=[])
    evidence = await manager.build_evidence(domain_id=domain_id, domain=target)
    assert evidence is not None

    assert evidence.domain == "phish.example"
    assert evidence.url == "https://phish.example/#/recover"
    assert evidence.screenshot_path == seed_shot
    assert evidence.backend_domains == [
        "whale-app-poxe2.ondigitalocean.app",
        "walrus-app-o5hvw.ondigitalocean.app",
    ]
    assert any("ipdata" in r.lower() for r in evidence.api_keys_found)
    assert evidence.hosting_provider == "cloudflare"

    await db.close()


class _FakeResponse:
    def __init__(self, *, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _FakeAsyncClient:
    def __init__(self, *, get_text: str):
        self._get_text = get_text
        self.get_calls: list[str] = []
        self.post_calls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url: str, *args, **kwargs):
        self.get_calls.append(url)
        return _FakeResponse(status_code=200, text=self._get_text)

    async def post(self, url: str, *args, **kwargs):
        self.post_calls.append(url)
        return _FakeResponse(status_code=200, text="")


@pytest.mark.asyncio
async def test_google_form_reporter_returns_manual_required_when_captcha_detected(monkeypatch):
    import httpx

    def fake_async_client(*args, **kwargs):
        return _FakeAsyncClient(get_text="<html>reCAPTCHA</html>")

    monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)

    reporter = GoogleFormReporter()
    evidence = ReportEvidence(
        domain="example.com",
        url="https://example.com/",
        detected_at=datetime.now(),
        confidence_score=90,
    )
    result = await reporter.submit(evidence)
    assert result.status == ReportStatus.MANUAL_REQUIRED


@pytest.mark.asyncio
async def test_cloudflare_reporter_returns_manual_required_when_turnstile_detected(monkeypatch):
    import httpx

    def fake_async_client(*args, **kwargs):
        return _FakeAsyncClient(get_text="<div>cf-turnstile</div>")

    monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)

    reporter = CloudflareReporter()
    evidence = ReportEvidence(
        domain="example.com",
        url="https://example.com/",
        detected_at=datetime.now(),
        confidence_score=90,
    )
    result = await reporter.submit(evidence)
    assert result.status == ReportStatus.MANUAL_REQUIRED
