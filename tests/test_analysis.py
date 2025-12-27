import socket
from datetime import datetime
from types import SimpleNamespace

import pytest

from src.analyzer.browser import BrowserResult
from src.analyzer.external_intel import ExternalIntelResult, URLScanResult
from src.pipeline.analysis import AnalysisEngine


class DummyExternalIntel:
    def __init__(self):
        self.query_all_called = False
        self.query_urlscan_best_called = False

    async def query_all(self, domain: str):
        self.query_all_called = True
        return ExternalIntelResult(score=0, reasons=[])

    async def query_urlscan_best(self, domain: str):
        self.query_urlscan_best_called = True
        return URLScanResult(found=True, scan_id="scan1", result_url="https://urlscan.io/result/scan1/")


class DummyDatabase:
    def __init__(self):
        self.status_updates: list = []
        self.analysis_updates: list = []

    async def update_domain_status(self, domain_id, status):
        self.status_updates.append((domain_id, status))

    async def update_domain_analysis(self, **kwargs):
        self.analysis_updates.append(kwargs)

    async def get_domain_by_id(self, domain_id):
        return {"status": "pending"}


class DummyEvidenceStore:
    def __init__(self):
        self.saved_analysis = None

    async def save_analysis(self, domain, data):
        self.saved_analysis = data

    async def save_screenshot(self, domain, data, suffix=""):
        return None

    def clear_exploration_screenshots(self, domain):
        return 0

    async def save_html(self, domain, html):
        return None

    def get_evidence_path(self, domain):
        return f"/tmp/{domain}"

    def get_screenshot_path(self, domain):
        return None

    def get_all_screenshot_paths(self, domain):
        return []

    def get_domain_id(self, domain):
        return 1


class DummyTemporal:
    def __init__(self):
        self.snapshots: list = []

    def add_snapshot(self, **kwargs):
        snapshot = SimpleNamespace(
            timestamp=kwargs.get("timestamp") or datetime.now(),
            reasons=kwargs.get("reasons", []),
            score=kwargs.get("score", 0),
            verdict=kwargs.get("verdict"),
        )
        self.snapshots.append(snapshot)

    def analyze(self, domain):
        return SimpleNamespace(cloaking_detected=False, cloaking_confidence=0)

    def get_snapshots(self, domain):
        return list(self.snapshots)


class DummyInfrastructure:
    async def analyze(self, domain):
        return SimpleNamespace(risk_score=0, risk_reasons=[], tls=None, hosting=None, domain_info=None)


class DummyBrowser:
    def __init__(self, result: BrowserResult):
        self._result = result

    async def analyze(self, domain: str):
        return self._result


class DummyThreatIntelUpdater:
    def extract_matched_backends(self, endpoints):
        return []

    def extract_matched_api_keys(self, reasons):
        return []

    def should_learn(self, **kwargs):
        return False

    def learn(self, **kwargs):
        return SimpleNamespace(updated=False, version="", added_to_frontends=[], added_to_api_keys=[])


class DummyReportManager:
    async def ensure_pending_reports(self, **kwargs):
        return None

    async def report_domain(self, **kwargs):
        return {}

    def format_results_summary(self, results):
        return ""

    def get_available_platforms(self):
        return []


class DummyBot:
    async def send_alert(self, *args, **kwargs):
        return None

    async def send_message(self, *args, **kwargs):
        return None


@pytest.mark.asyncio
async def test_urlscan_history_runs_on_timeout(monkeypatch):
    browser_result = BrowserResult(domain="timeout.test", success=False, error="Timed out")

    external_intel = DummyExternalIntel()
    database = DummyDatabase()
    evidence_store = DummyEvidenceStore()
    temporal = DummyTemporal()
    infrastructure = DummyInfrastructure()
    browser = DummyBrowser(browser_result)

    config = SimpleNamespace(
        urlscan_submit_enabled=False,
        urlscan_api_key="",
        urlscan_submit_visibility="unlisted",
        analysis_score_threshold=50,
        report_require_approval=False,
        report_min_score=80,
        allowlist=set(),
    )

    engine = AnalysisEngine(
        config=config,
        database=database,
        evidence_store=evidence_store,
        browser=browser,
        infrastructure=infrastructure,
        temporal=temporal,
        external_intel=external_intel,
        detector=SimpleNamespace(),
        cluster_manager=None,
        threat_intel_updater=DummyThreatIntelUpdater(),
        report_manager=DummyReportManager(),
        bot=DummyBot(),
    )

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 0))],
    )

    await engine.analyze({"id": 1, "domain": "timeout.test", "domain_score": 10, "reasons": []})

    assert external_intel.query_urlscan_best_called is True
    assert evidence_store.saved_analysis is not None
    reasons = evidence_store.saved_analysis.get("reasons", [])
    assert any("urlscan.io historical scan with wallet/seed UI" in reason for reason in reasons)
    assert evidence_store.saved_analysis.get("verdict") == "high"
    assert evidence_store.saved_analysis.get("score", 0) >= config.analysis_score_threshold


@pytest.mark.asyncio
async def test_urlscan_history_bumps_unresolvable_domains(monkeypatch):
    external_intel = DummyExternalIntel()
    database = DummyDatabase()
    evidence_store = DummyEvidenceStore()
    temporal = DummyTemporal()
    infrastructure = DummyInfrastructure()
    browser = DummyBrowser(BrowserResult(domain="no-dns.test", success=False, error="DNS failed"))

    config = SimpleNamespace(
        urlscan_submit_enabled=False,
        urlscan_api_key="",
        urlscan_submit_visibility="unlisted",
        analysis_score_threshold=70,
        report_require_approval=False,
        report_min_score=80,
        allowlist=set(),
    )

    engine = AnalysisEngine(
        config=config,
        database=database,
        evidence_store=evidence_store,
        browser=browser,
        infrastructure=infrastructure,
        temporal=temporal,
        external_intel=external_intel,
        detector=SimpleNamespace(),
        cluster_manager=None,
        threat_intel_updater=DummyThreatIntelUpdater(),
        report_manager=DummyReportManager(),
        bot=DummyBot(),
    )

    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror("No DNS")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    await engine.analyze({"id": 2, "domain": "no-dns.test", "domain_score": 5, "reasons": []})

    assert external_intel.query_urlscan_best_called is True
    assert evidence_store.saved_analysis is not None
    assert evidence_store.saved_analysis.get("verdict") == "high"
    assert evidence_store.saved_analysis.get("score", 0) >= config.analysis_score_threshold
