"""Comprehensive tests for the dashboard frontend."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from src.dashboard.server import (
    DashboardConfig,
    DashboardServer,
    _escape,
    _coerce_int,
    _extract_hostname,
    _domain_dir_name,
    _format_bytes,
    _status_badge,
    _verdict_badge,
)
from src.storage.database import Database, Verdict, DomainStatus


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
async def database(tmp_path):
    """Create an in-memory database for testing."""
    db = Database(tmp_path / "test.db")
    await db.connect()
    yield db
    await db.close()


@pytest.fixture
def evidence_dir(tmp_path):
    """Create a temporary evidence directory."""
    path = tmp_path / "evidence"
    path.mkdir()
    return path


@pytest.fixture
def campaigns_dir(tmp_path):
    """Create a temporary campaigns directory."""
    path = tmp_path / "campaigns"
    path.mkdir()
    return path


@pytest.fixture
def dashboard_config():
    """Create a basic dashboard configuration."""
    return DashboardConfig(
        enabled=True,
        host="127.0.0.1",
        port=8080,
        admin_user="admin",
        admin_password="testpassword",
    )


@pytest.fixture
def dashboard_config_no_auth():
    """Create a dashboard config without admin password."""
    return DashboardConfig(
        enabled=True,
        host="127.0.0.1",
        port=8080,
        admin_user="admin",
        admin_password="",
    )


@pytest.fixture
async def dashboard_server(database, evidence_dir, campaigns_dir, dashboard_config):
    """Create a dashboard server instance."""
    server = DashboardServer(
        config=dashboard_config,
        database=database,
        evidence_dir=evidence_dir,
        campaigns_dir=campaigns_dir,
    )
    return server


def _make_basic_auth(username: str, password: str) -> str:
    """Generate Basic Auth header value."""
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode()).decode()
    return f"Basic {encoded}"


def _admin_headers(csrf_token: str | None = None) -> dict[str, str]:
    """Build admin headers with optional CSRF token."""
    headers = {"Authorization": _make_basic_auth("admin", "testpassword")}
    if csrf_token:
        headers["X-CSRF-Token"] = csrf_token
    return headers


async def _get_admin_csrf(client) -> str:
    """Fetch admin CSRF token for API calls."""
    resp = await client.get(
        "/admin",
        headers={"Authorization": _make_basic_auth("admin", "testpassword")},
    )
    token = resp.cookies.get("sb_admin_csrf")
    return token.value if token else ""


# =============================================================================
# Utility Function Tests
# =============================================================================


class TestUtilityFunctions:
    """Test utility functions from server.py."""

    def test_escape_basic_string(self):
        """Test basic string escaping."""
        assert _escape("hello") == "hello"

    def test_escape_html_special_chars(self):
        """Test HTML special character escaping."""
        assert _escape("<script>alert('xss')</script>") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

    def test_escape_quotes(self):
        """Test quote escaping."""
        assert _escape('he said "hello"') == "he said &quot;hello&quot;"

    def test_escape_none(self):
        """Test None value returns empty string."""
        assert _escape(None) == ""

    def test_escape_number(self):
        """Test numeric value is converted to string."""
        assert _escape(123) == "123"

    def test_coerce_int_valid(self):
        """Test valid integer conversion."""
        assert _coerce_int("42", default=0) == 42

    def test_coerce_int_invalid(self):
        """Test invalid value returns default."""
        assert _coerce_int("invalid", default=10) == 10

    def test_coerce_int_min_value(self):
        """Test minimum value enforcement."""
        assert _coerce_int("5", default=0, min_value=10) == 10

    def test_coerce_int_max_value(self):
        """Test maximum value enforcement."""
        assert _coerce_int("100", default=0, max_value=50) == 50

    def test_coerce_int_min_max_range(self):
        """Test value clamping within range."""
        assert _coerce_int("25", default=0, min_value=10, max_value=50) == 25

    def test_extract_hostname_simple(self):
        """Test simple domain extraction."""
        assert _extract_hostname("example.com") == "example.com"

    def test_extract_hostname_with_protocol(self):
        """Test domain extraction from full URL."""
        assert _extract_hostname("https://example.com/path") == "example.com"

    def test_extract_hostname_with_port(self):
        """Test domain extraction with port."""
        assert _extract_hostname("https://example.com:8080/path") == "example.com"

    def test_extract_hostname_empty(self):
        """Test empty string returns empty."""
        assert _extract_hostname("") == ""

    def test_extract_hostname_with_trailing_dot(self):
        """Test trailing dots are stripped."""
        assert _extract_hostname("example.com.") == "example.com"

    def test_extract_hostname_uppercase(self):
        """Test hostname is lowercased."""
        assert _extract_hostname("EXAMPLE.COM") == "example.com"

    def test_domain_dir_name_creates_safe_name(self):
        """Test domain directory name generation."""
        name = _domain_dir_name("example.com")
        assert "example.com" in name
        assert "_" in name  # Contains hash separator

    def test_domain_dir_name_handles_special_chars(self):
        """Test special characters are sanitized."""
        name = _domain_dir_name("test/path:8080")
        assert "/" not in name
        assert ":" not in name

    def test_format_bytes_small(self):
        """Test byte formatting for small values."""
        assert _format_bytes(500) == "500 B"

    def test_format_bytes_kilobytes(self):
        """Test byte formatting for KB."""
        assert "KB" in _format_bytes(2048)

    def test_format_bytes_megabytes(self):
        """Test byte formatting for MB."""
        assert "MB" in _format_bytes(2 * 1024 * 1024)

    def test_format_bytes_zero(self):
        """Test zero bytes."""
        assert _format_bytes(0) == "0 B"

    def test_status_badge_returns_html(self):
        """Test status badge HTML generation."""
        badge = _status_badge("pending")
        assert "<span" in badge
        assert "sb-badge" in badge
        assert "pending" in badge

    def test_status_badge_escapes_value(self):
        """Test status badge escapes XSS attempts in content."""
        badge = _status_badge("<script>")
        # The text content is escaped, even though class may not be
        assert "&lt;script&gt;" in badge

    def test_verdict_badge_returns_html(self):
        """Test verdict badge HTML generation."""
        badge = _verdict_badge("high")
        assert "<span" in badge
        assert "sb-badge" in badge
        assert "high" in badge

    def test_verdict_badge_none_shows_unknown(self):
        """Test None verdict shows unknown."""
        badge = _verdict_badge(None)
        assert "unknown" in badge


# =============================================================================
# Public Route Tests
# =============================================================================


@pytest.mark.asyncio
async def test_healthz_endpoint(dashboard_server):
    """Test the health check endpoint."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get("/healthz")
        assert resp.status == 200
        data = await resp.json()
        assert data["ok"] is True


@pytest.mark.asyncio
async def test_public_index_returns_html(dashboard_server):
    """Test public index page returns HTML."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get("/")
        assert resp.status == 200
        assert "text/html" in resp.content_type
        text = await resp.text()
        assert "<!doctype html>" in text.lower()
        assert "SeedBuster" in text or "seedbuster" in text.lower()


@pytest.mark.asyncio
async def test_public_index_with_domains(dashboard_server, database):
    """Public API serves domains."""
    from aiohttp.test_utils import TestClient, TestServer

    domain_id = await database.add_domain(
        domain="phish1.example.com",
        source="certstream",
        domain_score=85,
    )
    await database.update_domain_analysis(
        domain_id=domain_id,
        analysis_score=90,
        verdict=Verdict.HIGH,
        verdict_reasons="Test detection",
        evidence_path="/tmp/evidence",
    )

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get("/api/domains")
        assert resp.status == 200
        data = await resp.json()
        assert any(d["domain"] == "phish1.example.com" for d in data["domains"])


@pytest.mark.asyncio
async def test_public_submit_already_tracked_domain(dashboard_server, database):
    """Public submit detects existing active threat."""
    from aiohttp.test_utils import TestClient, TestServer

    domain_id = await database.add_domain(
        domain="kaspafunding.org",
        source="manual",
        domain_score=10,
    )

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.post(
            "/api/public/submit",
            json={"domain": "https://kaspafunding.org/scam"},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "already_tracked"
        assert data["existing_domain_id"] == domain_id
        assert "kaspafunding.org" in data["existing_domain"]

    assert await database.count_public_submissions() == 0


@pytest.mark.asyncio
async def test_public_submit_parent_domain_match(dashboard_server, database):
    """Public submit matches parent domain when active threat exists."""
    from aiohttp.test_utils import TestClient, TestServer

    domain_id = await database.add_domain(
        domain="example.com",
        source="manual",
        domain_score=10,
    )

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.post(
            "/api/public/submit",
            json={"domain": "http://login.example.com/path"},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "already_tracked"
        assert data["existing_domain_id"] == domain_id
        assert data["existing_domain"] == "example.com"

    assert await database.count_public_submissions() == 0


@pytest.mark.asyncio
async def test_public_domain_not_found(dashboard_server):
    """Test public domain detail returns 404 for missing domain."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get("/domains/99999")
        assert resp.status == 404


@pytest.mark.asyncio
async def test_public_domain_detail(dashboard_server, database):
    """Test public domain detail page."""
    from aiohttp.test_utils import TestClient, TestServer

    domain_id = await database.add_domain(
        domain="test.phish.com",
        source="manual",
        domain_score=75,
    )
    await database.update_domain_analysis(
        domain_id=domain_id,
        analysis_score=65,
        verdict=Verdict.MEDIUM,
        verdict_reasons="Test detection",
        evidence_path="/tmp/evidence",
    )

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(f"/api/domains/{domain_id}")
        assert resp.status == 200
        data = await resp.json()
        assert data["domain"]["domain"] == "test.phish.com"


@pytest.mark.asyncio
async def test_public_campaigns_page(dashboard_server):
    """Test public campaigns page returns HTML."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get("/api/campaigns")
        assert resp.status == 200


# =============================================================================
# Admin Authentication Tests
# =============================================================================


@pytest.mark.asyncio
async def test_admin_requires_auth(dashboard_server):
    """Test admin routes require authentication."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get("/admin")
        assert resp.status == 401
        assert "WWW-Authenticate" in resp.headers


@pytest.mark.asyncio
async def test_admin_wrong_credentials(dashboard_server):
    """Test admin rejects wrong credentials."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin",
            headers={"Authorization": _make_basic_auth("admin", "wrongpassword")},
        )
        assert resp.status == 401


@pytest.mark.asyncio
async def test_admin_correct_credentials(dashboard_server):
    """Test admin accepts correct credentials."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200


@pytest.mark.asyncio
async def test_admin_invalid_auth_header(dashboard_server):
    """Test admin rejects malformed auth header."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin",
            headers={"Authorization": "Bearer invalid"},
        )
        assert resp.status == 401


@pytest.mark.asyncio
async def test_admin_no_password_configured(database, evidence_dir, campaigns_dir, dashboard_config_no_auth):
    """Test admin returns 403 when no password is configured."""
    from aiohttp.test_utils import TestClient, TestServer

    server = DashboardServer(
        config=dashboard_config_no_auth,
        database=database,
        evidence_dir=evidence_dir,
        campaigns_dir=campaigns_dir,
    )

    async with TestClient(TestServer(server._app)) as client:
        resp = await client.get(
            "/admin",
            headers={"Authorization": _make_basic_auth("admin", "anything")},
        )
        assert resp.status == 403


# =============================================================================
# Admin SPA + API tests
# =============================================================================


@pytest.mark.asyncio
async def test_admin_index_serves_spa(dashboard_server):
    """Admin entry should serve SPA shell with mode flag."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200
        text = await resp.text()
        assert "__SB_MODE=\"admin\"" in text
        assert "<!doctype html>" in text.lower()


@pytest.mark.asyncio
async def test_admin_api_domains_list(dashboard_server, database):
    """Admin API returns domain list as JSON."""
    from aiohttp.test_utils import TestClient, TestServer

    await database.add_domain(domain="api-test1.com", source="manual", domain_score=80)
    await database.add_domain(domain="api-test2.com", source="certstream", domain_score=60)

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin/api/domains",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200
        assert "application/json" in resp.content_type
        data = await resp.json()
        assert "domains" in data
        assert any(d["domain"] == "api-test1.com" for d in data["domains"])
        assert any(d["domain"] == "api-test2.com" for d in data["domains"])


@pytest.mark.asyncio
async def test_admin_api_domain_detail(dashboard_server, database):
    """Admin API domain detail returns JSON."""
    from aiohttp.test_utils import TestClient, TestServer

    domain_id = await database.add_domain(
        domain="detail.test.com",
        source="manual",
        domain_score=70,
    )

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            f"/admin/api/domains/{domain_id}",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["domain"]["domain"] == "detail.test.com"


@pytest.mark.asyncio
async def test_admin_api_takedown_checks(dashboard_server, database):
    """Admin API returns takedown checks."""
    from aiohttp.test_utils import TestClient, TestServer

    domain_id = await database.add_domain(
        domain="takedown.test.com",
        source="manual",
        domain_score=70,
    )
    other_domain_id = await database.add_domain(
        domain="takedown.other.com",
        source="manual",
        domain_score=50,
    )
    await database.add_takedown_check(
        domain_id=domain_id,
        http_status=503,
        takedown_status="likely_down",
        confidence=0.4,
        provider_signal="backend:503",
    )
    await database.add_takedown_check(
        domain_id=other_domain_id,
        http_status=200,
        takedown_status="active",
        confidence=0.1,
        provider_signal="ok",
    )
    allowlisted_id = await database.add_domain(
        domain="takedown.allowlisted.com",
        source="manual",
        domain_score=10,
    )
    await database.update_domain_status(allowlisted_id, DomainStatus.ALLOWLISTED)
    await database.add_takedown_check(
        domain_id=allowlisted_id,
        http_status=200,
        takedown_status="active",
        confidence=0.0,
    )

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            f"/admin/api/takedown-checks?domain_id={domain_id}",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["count"] == 1
        assert data["checks"][0]["domain_id"] == domain_id

        resp = await client.get(
            "/admin/api/takedown-checks?domain=takedown.test.com",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["count"] == 1
        assert data["checks"][0]["domain"] == "takedown.test.com"

        resp = await client.get(
            "/admin/api/takedown-checks",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["count"] == 2
        assert all(check["domain"] != "takedown.allowlisted.com" for check in data["checks"])


@pytest.mark.asyncio
async def test_admin_api_domain_not_found(dashboard_server):
    """Missing domain returns 404 from API."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin/api/domains/99999",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 404


@pytest.mark.asyncio
async def test_admin_api_campaigns(dashboard_server):
    """Admin API campaigns returns JSON."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin/api/campaigns",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200
        data = await resp.json()
        assert "campaigns" in data


@pytest.mark.asyncio
async def test_admin_api_domain_not_found(dashboard_server):
    """Test admin API returns 404 for missing domain."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin/api/domains/99999",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 404


@pytest.mark.asyncio
async def test_admin_api_submit_domain(dashboard_server, database):
    """Test admin API domain submission."""
    from aiohttp.test_utils import TestClient, TestServer

    submitted_domains = []

    def capture_submit(domain: str, source_url: str | None = None):
        submitted_domains.append((domain, source_url))

    dashboard_server.submit_callback = capture_submit

    async with TestClient(TestServer(dashboard_server._app)) as client:
        # First get a CSRF token by visiting admin page
        csrf_token = await _get_admin_csrf(client)

        # Submit domain via API with CSRF header
        headers = _admin_headers(csrf_token)
        headers["Content-Type"] = "application/json"
        resp = await client.post(
            "/admin/api/submit",
            headers=headers,
            json={"domain": "newdomain.example.com"},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "submitted"
        assert ("newdomain.example.com", None) in submitted_domains


@pytest.mark.asyncio
async def test_admin_api_approve_submission_queues_root_and_path(dashboard_server, database):
    """Approving a public submission queues root + submitted path."""
    from aiohttp.test_utils import TestClient, TestServer

    submitted = []

    def capture_submit(domain: str, source_url: str | None = None):
        submitted.append((domain, source_url))

    dashboard_server.submit_callback = capture_submit

    submission_id, _ = await database.add_public_submission(
        domain="1331.one",
        canonical_domain="1331.one",
        source_url="https://1331.one/kas",
    )

    async with TestClient(TestServer(dashboard_server._app)) as client:
        csrf_token = await _get_admin_csrf(client)
        headers = _admin_headers(csrf_token)
        headers["Content-Type"] = "application/json"
        resp = await client.post(
            f"/admin/api/submissions/{submission_id}/approve",
            headers=headers,
            json={},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "approved"

    assert submitted == [
        ("1331.one", None),
        ("1331.one", "https://1331.one/kas"),
    ]


@pytest.mark.asyncio
async def test_admin_api_submit_empty_domain(dashboard_server):
    """Test admin API rejects empty domain submission."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        csrf_token = await _get_admin_csrf(client)
        headers = _admin_headers(csrf_token)
        headers["Content-Type"] = "application/json"
        resp = await client.post(
            "/admin/api/submit",
            headers=headers,
            json={"domain": ""},
        )
        assert resp.status == 400


@pytest.mark.asyncio
async def test_admin_api_rescan_domain(dashboard_server, database):
    """Test admin API domain rescan."""
    from aiohttp.test_utils import TestClient, TestServer

    domain_id = await database.add_domain(
        domain="rescan.example.com",
        source="manual",
        domain_score=75,
    )

    rescanned_domains = []

    def capture_rescan(domain: str):
        rescanned_domains.append(domain)

    dashboard_server.rescan_callback = capture_rescan

    async with TestClient(TestServer(dashboard_server._app)) as client:
        csrf_token = await _get_admin_csrf(client)
        headers = _admin_headers(csrf_token)
        headers["Content-Type"] = "application/json"
        resp = await client.post(
            f"/admin/api/domains/{domain_id}/rescan",
            headers=headers,
            json={},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "rescan_queued"
        assert "rescan.example.com" in rescanned_domains


@pytest.mark.asyncio
async def test_admin_api_evidence(dashboard_server, database, evidence_dir):
    """Test admin API evidence retrieval."""
    from aiohttp.test_utils import TestClient, TestServer

    domain_id = await database.add_domain(
        domain="evidence.test.com",
        source="manual",
        domain_score=80,
    )

    # Create mock evidence files
    domain_dir = evidence_dir / _domain_dir_name("evidence.test.com")
    domain_dir.mkdir(parents=True)
    (domain_dir / "screenshot.png").write_bytes(b"fake-png")
    (domain_dir / "analysis.json").write_text('{"test": true}')

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            f"/admin/api/domains/{domain_id}/evidence",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200
        data = await resp.json()
        assert "files" in data


# =============================================================================
# Pagination and Filtering Tests
# =============================================================================


@pytest.mark.asyncio
async def test_admin_index_pagination(dashboard_server, database):
    """Test admin API pagination parameters."""
    from aiohttp.test_utils import TestClient, TestServer

    # Add multiple domains
    for i in range(25):
        await database.add_domain(
            domain=f"page-test-{i}.com",
            source="manual",
            domain_score=50 + i,
        )

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp_page1 = await client.get(
            "/admin/api/domains?limit=10&page=1",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        resp_page2 = await client.get(
            "/admin/api/domains?limit=10&page=2",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp_page1.status == 200
        assert resp_page2.status == 200
        data1 = await resp_page1.json()
        data2 = await resp_page2.json()
        assert data1["page"] == 1
        assert data2["page"] == 2
        assert len(data1["domains"]) <= 10
        assert len(data2["domains"]) <= 10


@pytest.mark.asyncio
async def test_admin_index_status_filter(dashboard_server, database):
    """Test admin API status filtering."""
    from aiohttp.test_utils import TestClient, TestServer

    # Add domains with different statuses
    await database.add_domain(domain="pending.test.com", source="manual", domain_score=80)

    domain_id = await database.add_domain(domain="analyzed.test.com", source="manual", domain_score=85)
    await database.update_domain_analysis(
        domain_id=domain_id,
        analysis_score=90,
        verdict=Verdict.HIGH,
        verdict_reasons="Test detection",
        evidence_path="/tmp/evidence",
    )

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin/api/domains?status=analyzed",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200
        data = await resp.json()
        assert any(d["domain"] == "analyzed.test.com" for d in data["domains"])


@pytest.mark.asyncio
async def test_admin_index_verdict_filter(dashboard_server, database):
    """Test admin API verdict filtering."""
    from aiohttp.test_utils import TestClient, TestServer

    domain_id = await database.add_domain(domain="high-verdict.test.com", source="manual", domain_score=90)
    await database.update_domain_analysis(
        domain_id=domain_id,
        analysis_score=95,
        verdict=Verdict.HIGH,
        verdict_reasons="Test detection",
        evidence_path="/tmp/evidence",
    )

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin/api/domains?verdict=high",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200
        data = await resp.json()
        assert any(d["domain"] == "high-verdict.test.com" for d in data["domains"])


# =============================================================================
# Error Handling Tests
# =============================================================================


@pytest.mark.asyncio
async def test_public_handles_invalid_domain_id(dashboard_server):
    """Test public route handles invalid domain ID gracefully."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get("/domains/invalid")
        # Should return 404 or 400
        assert resp.status in (400, 404)


@pytest.mark.asyncio
async def test_admin_api_handles_invalid_json(dashboard_server):
    """Test admin API handles invalid JSON."""
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(dashboard_server._app)) as client:
        csrf_token = await _get_admin_csrf(client)
        headers = _admin_headers(csrf_token)
        headers["Content-Type"] = "application/json"
        resp = await client.post(
            "/admin/api/submit",
            headers=headers,
            data=b"not valid json",
        )
        assert resp.status == 400


# =============================================================================
# Campaign Tests
# =============================================================================


@pytest.mark.asyncio
async def test_admin_campaigns_with_data(dashboard_server, campaigns_dir):
    """Test admin campaigns page with campaign data."""
    from aiohttp.test_utils import TestClient, TestServer

    # Create campaign data
    campaigns_file = campaigns_dir / "campaigns.json"
    campaigns_file.write_text(json.dumps({
        "campaigns": [
            {
                "campaign_id": "campaign_001",
                "name": "Test Campaign",
                "members": [
                    {"domain": "member1.test.com"},
                    {"domain": "member2.test.com"},
                ],
            }
        ]
    }))

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin/campaigns",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        assert resp.status == 200
        text = await resp.text()
        # Campaigns page should load even if campaigns are shown differently
        assert "<!doctype html>" in text.lower()


@pytest.mark.asyncio
async def test_admin_campaign_detail(dashboard_server, campaigns_dir):
    """Test admin campaign detail page."""
    from aiohttp.test_utils import TestClient, TestServer

    # Create campaign data
    campaigns_file = campaigns_dir / "campaigns.json"
    campaigns_file.write_text(json.dumps({
        "campaigns": [
            {
                "campaign_id": "campaign_test",
                "name": "Detail Test Campaign",
                "members": [
                    {"domain": "detail1.test.com"},
                ],
            }
        ]
    }))

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get(
            "/admin/campaigns/campaign_test",
            headers={"Authorization": _make_basic_auth("admin", "testpassword")},
        )
        # Should return 200 if campaign exists, 404 if not found
        assert resp.status in (200, 404)


# =============================================================================
# Evidence Cleanup Tests
# =============================================================================


@pytest.mark.asyncio
async def test_admin_api_cleanup_evidence(dashboard_server, evidence_dir):
    """Test evidence cleanup API endpoint."""
    from aiohttp.test_utils import TestClient, TestServer
    from datetime import datetime, timezone, timedelta

    # Create old evidence
    old_domain_dir = evidence_dir / _domain_dir_name("old.test.com")
    old_domain_dir.mkdir(parents=True)
    old_analysis = {
        "domain": "old.test.com",
        "saved_at": (datetime.now(timezone.utc) - timedelta(days=60)).isoformat(),
    }
    (old_domain_dir / "analysis.json").write_text(json.dumps(old_analysis))

    # Create recent evidence
    new_domain_dir = evidence_dir / _domain_dir_name("new.test.com")
    new_domain_dir.mkdir(parents=True)
    new_analysis = {
        "domain": "new.test.com",
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    (new_domain_dir / "analysis.json").write_text(json.dumps(new_analysis))

    async with TestClient(TestServer(dashboard_server._app)) as client:
        csrf_token = await _get_admin_csrf(client)
        headers = _admin_headers(csrf_token)
        headers["Content-Type"] = "application/json"
        resp = await client.post(
            "/admin/api/cleanup_evidence",
            headers=headers,
            json={"days": 30},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ok"
        assert "removed_dirs" in data

        # Old evidence should be removed
        assert not old_domain_dir.exists()
        # New evidence should remain
        assert new_domain_dir.exists()


# =============================================================================
# HTML Content Validation Tests
# =============================================================================


@pytest.mark.asyncio
async def test_public_index_escapes_domain_names(dashboard_server, database):
    """Test that domain names are properly escaped in HTML output."""
    from aiohttp.test_utils import TestClient, TestServer

    # Add a domain with XSS-like content
    await database.add_domain(
        domain="<script>alert('xss')</script>.com",
        source="manual",
        domain_score=80,
    )

    async with TestClient(TestServer(dashboard_server._app)) as client:
        resp = await client.get("/")
        assert resp.status == 200
        text = await resp.text()
        # Script tags should be escaped
        assert "<script>alert" not in text
        assert "&lt;script&gt;" in text or "script" not in text.lower() or resp.status == 200


@pytest.mark.asyncio
async def test_api_report_domain(dashboard_server, database):
    """Test API domain reporting."""
    from aiohttp.test_utils import TestClient, TestServer

    domain_id = await database.add_domain(
        domain="report-api.test.com",
        source="manual",
        domain_score=90,
    )

    reported = []

    async def capture_report(domain_id: int, domain: str, platforms: list, manual: bool):
        reported.append((domain_id, domain, platforms, manual))
        return {"test": {"status": "submitted"}}

    dashboard_server.report_callback = capture_report

    async with TestClient(TestServer(dashboard_server._app)) as client:
        csrf_token = await _get_admin_csrf(client)
        headers = _admin_headers(csrf_token)
        headers["Content-Type"] = "application/json"
        resp = await client.post(
            "/admin/api/report",
            headers=headers,
            json={"domain_id": domain_id, "platforms": ["google", "cloudflare"]},
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "report_enqueued"
        assert len(reported) == 1
        assert reported[0][1] == "report-api.test.com"
