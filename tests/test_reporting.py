"""Tests for reporting evidence and reporter fallbacks."""

from __future__ import annotations

from datetime import datetime

import pytest

from src.reporter.base import ReportEvidence, ReportStatus
from src.reporter.base import BaseReporter, ReportResult
from src.reporter.cloudflare import CloudflareReporter
from src.reporter.google_form import GoogleFormReporter
from src.reporter.hosting_provider import HostingProviderReporter
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


class _ManualOnlyReporter(BaseReporter):
    platform_name = "manual"

    def __init__(self, *, message: str):
        super().__init__()
        self._configured = True
        self._message = message

    async def submit(self, evidence: ReportEvidence) -> ReportResult:  # noqa: ARG002
        return ReportResult(
            platform=self.platform_name,
            status=ReportStatus.MANUAL_REQUIRED,
            message=self._message,
        )


@pytest.mark.asyncio
async def test_report_manager_saves_manual_instruction_file(tmp_path):
    db = Database(tmp_path / "seedbuster.db")
    await db.connect()

    target = "example.com/path"
    domain_id = await db.add_domain(domain=target, source="manual", domain_score=90)
    assert domain_id is not None

    store = EvidenceStore(tmp_path / "evidence")
    await store.save_analysis(target, {
        "domain": target,
        "final_url": "https://example.com/path",
        "reasons": ["Seed phrase form detected"],
        "suspicious_endpoints": ["https://backend.example/api/form"],
    })

    message = "Manual submission required: https://provider.example/report\n\nURL: https://example.com/path"
    reporter = _ManualOnlyReporter(message=message)
    manager = ReportManager(database=db, evidence_store=store, enabled_platforms=["manual"])
    manager.reporters = {"manual": reporter}

    results = await manager.report_domain(domain_id=domain_id, domain=target, platforms=["manual"])
    assert results["manual"].status == ReportStatus.MANUAL_REQUIRED

    instruction_path = store.get_report_instructions_path(target, "manual")
    assert instruction_path.exists()
    content = instruction_path.read_text(encoding="utf-8")
    assert "SeedBuster Manual Report Instructions" in content
    assert "Platform: manual" in content
    assert "Manual submission required:" in content
    assert "Evidence Summary:" in content
    assert "URL: https://example.com/path" in content

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


@pytest.mark.asyncio
async def test_hosting_provider_reporter_returns_manual_required_for_form_provider():
    reporter = HostingProviderReporter()
    evidence = ReportEvidence(
        domain="example.com",
        url="https://example.com/",
        detected_at=datetime.now(),
        confidence_score=90,
        hosting_provider="aws",
    )
    result = await reporter.submit(evidence)
    assert result.status == ReportStatus.MANUAL_REQUIRED
    assert "support.aws.amazon.com" in (result.message or "")


@pytest.mark.asyncio
async def test_hosting_provider_reporter_returns_manual_required_for_email_provider():
    reporter = HostingProviderReporter(reporter_email="analyst@example.com")
    evidence = ReportEvidence(
        domain="example.com",
        url="https://example.com/",
        detected_at=datetime.now(),
        confidence_score=90,
        hosting_provider="namecheap",
    )
    result = await reporter.submit(evidence)
    assert result.status == ReportStatus.MANUAL_REQUIRED
    assert "abuse@namecheap.com" in (result.message or "")
